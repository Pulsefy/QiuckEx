import AsyncStorage from "@react-native-async-storage/async-storage";
import NetInfo from "@react-native-community/netinfo";
import { Platform } from "react-native";

import { API_URL } from "../src/config/build";
import {
  captureUnhandledError,
  captureNativeCrash,
} from "./crash-monitoring";
import {
  enqueueAction,
  processOfflineQueue,
  registerActionHandler,
  registerConflictPolicy,
} from "./offline-queue";

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

/**
 * Storage layout for the device-token lifecycle. Three keys, all namespaced
 * under `quickex.deviceToken.*` so we can wipe the lot on sign-out without
 * touching other features.
 */
const STORAGE_KEYS = {
  token: "quickex.deviceToken.token.v1",
  installationId: "quickex.deviceToken.installationId.v1",
  publicKey: "quickex.deviceToken.publicKey.v1",
  registeredAt: "quickex.deviceToken.registeredAt.v1",
} as const;

// ---------------------------------------------------------------------------
// Offline-queue action constants
// ---------------------------------------------------------------------------

/**
 * Action type used to retry a failed device-token registration once the
 * device is back online. The handler posts the stored payload to the backend
 * so we never lose a refresh event because of a transient network blip.
 */
export const DEVICE_TOKEN_REGISTER_ACTION = "deviceToken.register";
/**
 * Action type used to retry a failed device-token deregistration (e.g. on
 * sign-out). Carries the `publicKey` so the backend can clear its row even
 * if the user is no longer authenticated.
 */
export const DEVICE_TOKEN_DEREGISTER_ACTION = "deviceToken.deregister";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type PermissionStatus = "granted" | "denied" | "undetermined";

export interface DeviceTokenRecord {
  /** Expo push token (or platform-native push token) */
  token: string;
  /** Platform the token belongs to */
  platform: "ios" | "android" | "web";
  /** Persisted installation id, used to detect reinstall/restore */
  installationId: string;
  /** Public key the token is currently registered for (if any) */
  publicKey?: string;
  /** Epoch ms when this record was last persisted */
  registeredAt: number;
}

export type RegisterResult =
  | { status: "registered"; token: string; alreadyRegistered: boolean }
  | { status: "denied"; reason: PermissionStatus }
  | { status: "skipped"; reason: "no-wallet" | "web-platform" | "simulator" }
  | { status: "queued"; reason: "offline" | "request-failed" }
  | { status: "failed"; reason: string };

export type DeregisterResult =
  | { status: "deregistered" }
  | { status: "skipped"; reason: "no-token" | "web-platform" | "no-wallet" }
  | { status: "queued"; reason: "offline" | "request-failed" }
  | { status: "failed"; reason: string };

// ---------------------------------------------------------------------------
// Backoff configuration
// ---------------------------------------------------------------------------

/**
 * Exponential backoff schedule (in ms) for the in-process retry loop.
 * Max 5 attempts, capped at 60s, so the total worst-case wait is ~60s.
 *
 * The values are also exported so tests can assert the schedule without
 * having to advance fake timers for every delay.
 */
export const REGISTRATION_BACKOFF_MS: readonly number[] = [
  1_000,
  2_000,
  4_000,
  8_000,
  16_000,
];
export const REGISTRATION_MAX_ATTEMPTS = 5;

// ---------------------------------------------------------------------------
// Internal helpers — module-level state
// ---------------------------------------------------------------------------

let queueHandlersRegistered = false;

/**
 * In-flight guard so we never spawn two parallel `registerDeviceToken()`
 * calls. Without this, an OS-driven refresh and a foreground-resume
 * reconcile could double-register the same token in the same tick.
 */
let inFlightRegistration: Promise<RegisterResult> | null = null;

/**
 * Test-only hook to clear module state. Production code never calls this.
 */
export function __resetDeviceTokenRegistrationState(): void {
  inFlightRegistration = null;
  queueHandlersRegistered = false;
}

/**
 * Test-only helper to plant a stored device-token record. Production code
 * never calls this — it exists so tests can simulate a "previous install"
 * for the supersession flow without having to seed AsyncStorage by hand.
 */
export async function setStoredDeviceTokenForTest(
  record: DeviceTokenRecord,
): Promise<void> {
  await writeJson(STORAGE_KEYS.token, record);
  await AsyncStorage.setItem(STORAGE_KEYS.installationId, record.installationId);
  if (record.publicKey) {
    await AsyncStorage.setItem(STORAGE_KEYS.publicKey, record.publicKey);
  }
  await AsyncStorage.setItem(
    STORAGE_KEYS.registeredAt,
    String(record.registeredAt),
  );
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

function getApiBaseUrl(): string {
  return API_URL.replace(/\/$/, "");
}

async function readJson<T>(key: string): Promise<T | null> {
  try {
    const raw = await AsyncStorage.getItem(key);
    if (!raw) return null;
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

async function writeJson(key: string, value: unknown): Promise<void> {
  try {
    await AsyncStorage.setItem(key, JSON.stringify(value));
  } catch (error) {
    console.warn(`[device-token] Failed to persist ${key}:`, error);
  }
}

export async function getStoredDeviceToken(): Promise<DeviceTokenRecord | null> {
  return readJson<DeviceTokenRecord>(STORAGE_KEYS.token);
}

export async function getStoredInstallationId(): Promise<string | null> {
  const raw = await AsyncStorage.getItem(STORAGE_KEYS.installationId);
  return raw ?? null;
}

export async function getStoredPublicKey(): Promise<string | null> {
  const raw = await AsyncStorage.getItem(STORAGE_KEYS.publicKey);
  return raw ?? null;
}

export async function clearStoredDeviceToken(): Promise<void> {
  await Promise.all(
    Object.values(STORAGE_KEYS).map((key) => AsyncStorage.removeItem(key)),
  );
}

// ---------------------------------------------------------------------------
// Installation id
// ---------------------------------------------------------------------------

/**
 * Returns a stable id that survives app restarts on the same install but
 * rotates when the OS hands out a new one (reinstall, device restore,
 * browser clear-storage).
 *
 * We deliberately avoid pulling in `expo-application` so this service has
 * no new dependencies. Instead we generate a random id on first launch and
 * persist it; if the persisted id is ever missing, treat the install as
 * fresh and supersede whatever the backend already knows about.
 */
export async function getOrCreateInstallationId(): Promise<string> {
  const existing = await getStoredInstallationId();
  if (existing) return existing;

  const fresh = generateInstallationId();
  try {
    await AsyncStorage.setItem(STORAGE_KEYS.installationId, fresh);
  } catch (error) {
    // Storage failures should never crash token registration; we just lose
    // supersession detection for this session.
    console.warn("[device-token] Failed to persist installation id:", error);
  }
  return fresh;
}

function generateInstallationId(): string {
  // 16 random bytes hex-encoded; collision-resistant and URL-safe.
  const bytes = new Uint8Array(16);
  if (
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.getRandomValues === "function"
  ) {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Permission helpers
// ---------------------------------------------------------------------------

/**
 * Returns the current notification permission status without prompting.
 * `undetermined` means the OS has not been asked yet.
 */
export async function getPermissionStatus(): Promise<PermissionStatus> {
  const Notifications = getNotificationsModule();
  if (!Notifications?.getPermissionsAsync) return "denied";

  try {
    const result = await Notifications.getPermissionsAsync();
    return mapPermissionStatus(result);
  } catch {
    return "undetermined";
  }
}

/**
 * Requests notification permission if not already granted. Resolves to the
 * final status, which may still be `denied` if the user rejected the prompt.
 */
export async function ensureNotificationPermission(): Promise<PermissionStatus> {
  const Notifications = getNotificationsModule();
  if (!Notifications?.getPermissionsAsync) return "denied";

  const current = await Notifications.getPermissionsAsync();
  const currentStatus = mapPermissionStatus(current);

  if (currentStatus === "granted") return "granted";

  if (!Notifications.requestPermissionsAsync) return currentStatus;

  const requested = await Notifications.requestPermissionsAsync({
    ios: {
      allowAlert: true,
      allowBadge: true,
      allowSound: true,
    },
  });
  return mapPermissionStatus(requested);
}

function mapPermissionStatus(result: any): PermissionStatus {
  if (!result) return "undetermined";
  if (result.granted) return "granted";
  // expo-notifications reports canReturnAnswer / canAskAgain separately
  // but the only states that matter for our lifecycle are granted/denied.
  if (result.status === "granted") return "granted";
  if (result.status === "denied") return "denied";
  if (result.ios?.status === "granted") return "granted";
  return result.canAskAgain === false ? "denied" : "undetermined";
}

// ---------------------------------------------------------------------------
// Network helper
// ---------------------------------------------------------------------------

async function isOnline(): Promise<boolean> {
  try {
    const state = await NetInfo.fetch();
    return Boolean(state.isConnected && state.isInternetReachable !== false);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Native module accessor (kept tolerant of missing module in tests / web)
// ---------------------------------------------------------------------------

function getNotificationsModuleInternal(): any | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
    return require("expo-notifications");
  } catch {
    return null;
  }
}

/**
 * Exported accessor for the expo-notifications module. Tolerant of the
 * module being absent (e.g. on web, in tests, or before the native bundle
 * has finished loading).
 */
export function getNotificationsModule(): any | null {
  return getNotificationsModuleInternal();
}

// ---------------------------------------------------------------------------
// Token retrieval
// ---------------------------------------------------------------------------

/**
 * Asks the OS for a fresh push token. Returns `null` if permission is not
 * granted, if running on web/simulator, or if the native call rejects.
 */
export async function obtainDevicePushToken(): Promise<string | null> {
  const Notifications = getNotificationsModule();
  if (!Notifications) return null;

  // On web we cannot obtain a real device token.
  if (Platform.OS === "web") return null;

  // Constants.isDevice is exposed by expo-constants; false on simulators
  // where push tokens cannot be generated.
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
    const Constants = require("expo-constants");
    if (Constants?.isDevice === false) {
      return null;
    }
  } catch {
    // ignore — fall through and let getExpoPushTokenAsync throw if needed
  }

  try {
    if (typeof Notifications.getExpoPushTokenAsync === "function") {
      const result = await Notifications.getExpoPushTokenAsync();
      if (result?.data) return result.data;
    }
    if (typeof Notifications.getDevicePushTokenAsync === "function") {
      const result = await Notifications.getDevicePushTokenAsync();
      if (result?.data) return result.data;
    }
  } catch (error) {
    console.warn("[device-token] Failed to obtain push token:", error);
    return null;
  }

  return null;
}

// ---------------------------------------------------------------------------
// Backend integration
// ---------------------------------------------------------------------------

/**
 * POSTs the device token to the backend, scoped to the wallet's public key.
 * Used both for first-time registration and for refresh.
 *
 * Backend contract (matches the OpenAPI schema):
 *   PUT /notifications/preferences/:publicKey
 *   body: { channel: "push", pushToken: <token>, enabled: true }
 *
 * Throws on non-2xx so the offline queue / backoff loop can react.
 */
export async function postDeviceTokenToBackend(args: {
  publicKey: string;
  pushToken: string;
  installationId: string;
}): Promise<void> {
  const url = `${getApiBaseUrl()}/notifications/preferences/${encodeURIComponent(
    args.publicKey,
  )}`;
  const response = await fetch(url, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-Device-Installation-Id": args.installationId,
    },
    body: JSON.stringify({
      channel: "push",
      pushToken: args.pushToken,
      enabled: true,
    }),
  });

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      if (body?.message) detail = body.message;
    } catch {
      // ignore — keep the status code message
    }
    throw new Error(`Device token registration failed: ${detail}`);
  }
}

/**
 * Disables the push channel on the backend so stale tokens no longer
 * receive notifications.
 *
 * Backend contract:
 *   DELETE /notifications/preferences/:publicKey/push
 */
export async function postDeregisterToBackend(args: {
  publicKey: string;
  installationId: string;
}): Promise<void> {
  const url = `${getApiBaseUrl()}/notifications/preferences/${encodeURIComponent(
    args.publicKey,
  )}/push`;
  const response = await fetch(url, {
    method: "DELETE",
    headers: {
      Accept: "application/json",
      "X-Device-Installation-Id": args.installationId,
    },
  });

  if (!response.ok && response.status !== 404) {
    throw new Error(
      `Device token deregistration failed: HTTP ${response.status}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Offline-queue handler registration
// ---------------------------------------------------------------------------

/**
 * Registers the offline-queue handlers for register/deregister retries.
 * Idempotent: safe to call from multiple call sites.
 */
export function registerDeviceTokenQueueHandlers(): void {
  if (queueHandlersRegistered) return;
  queueHandlersRegistered = true;

  // A previously-failed registration should always be retried; the
  // backend upsert is idempotent for the same (publicKey, pushToken) pair.
  registerConflictPolicy(DEVICE_TOKEN_REGISTER_ACTION, "retry");
  registerActionHandler(
    DEVICE_TOKEN_REGISTER_ACTION,
    async (payload: unknown) => {
      const data = payload as
        | { publicKey: string; pushToken: string; installationId: string }
        | undefined;
      if (!data?.publicKey || !data?.pushToken || !data?.installationId) {
        throw new Error("deviceToken.register requires publicKey/pushToken/installationId");
      }
      await postDeviceTokenToBackend(data);
    },
  );

  // Deregister is best-effort; if it ultimately fails we still wipe the
  // local record so the user is signed out cleanly.
  registerConflictPolicy(DEVICE_TOKEN_DEREGISTER_ACTION, "drop");
  registerActionHandler(
    DEVICE_TOKEN_DEREGISTER_ACTION,
    async (payload: unknown) => {
      const data = payload as
        | { publicKey: string; installationId: string }
        | undefined;
      if (!data?.publicKey || !data?.installationId) {
        throw new Error("deviceToken.deregister requires publicKey/installationId");
      }
      await postDeregisterToBackend(data);
    },
  );
}

// ---------------------------------------------------------------------------
// Public API — registration
// ---------------------------------------------------------------------------

/**
 * Registers (or re-registers) the current device's push token with the
 * backend for the given Stellar public key.
 *
 * Lifecycle:
 *   1. Coalesce concurrent calls.
 *   2. Ensure permission; abort with `denied` if user rejected.
 *   3. Skip on web / simulator.
 *   4. Obtain a fresh token; compare to the stored one.
 *   5. POST to backend with exponential backoff (5 attempts).
 *   6. On permanent failure, enqueue to offline-queue and report to crash
 *      monitoring so engineers can see *why* notifications stopped.
 *   7. Persist the new record locally.
 */
export function registerDeviceToken(args: {
  publicKey: string | null | undefined;
  force?: boolean;
}): Promise<RegisterResult> {
  if (inFlightRegistration) {
    return inFlightRegistration;
  }

  const run = runRegisterDeviceToken(args).finally(() => {
    inFlightRegistration = null;
  });
  inFlightRegistration = run;
  return run;
}

async function runRegisterDeviceToken(args: {
  publicKey: string | null | undefined;
  force?: boolean;
}): Promise<RegisterResult> {
  registerDeviceTokenQueueHandlers();

  const { publicKey, force = false } = args;
  if (!publicKey) {
    return { status: "skipped", reason: "no-wallet" };
  }
  if (Platform.OS === "web") {
    return { status: "skipped", reason: "web-platform" };
  }

  const permission = await ensureNotificationPermission();
  if (permission !== "granted") {
    // If we previously had a token and the user just revoked permission,
    // make sure we drop the local record so we don't keep trying.
    if (permission === "denied") {
      await clearStoredDeviceToken();
    }
    return { status: "denied", reason: permission };
  }

  const token = await obtainDevicePushToken();
  if (!token) {
    return { status: "skipped", reason: "simulator" };
  }

  const installationId = await getOrCreateInstallationId();
  const stored = await getStoredDeviceToken();
  const alreadyRegistered =
    !force &&
    stored?.token === token &&
    stored?.publicKey === publicKey &&
    stored?.installationId === installationId;

  if (alreadyRegistered && stored) {
    return { status: "registered", token, alreadyRegistered: true };
  }

  if (!(await isOnline())) {
    await persistTokenRecord({
      token,
      platform: Platform.OS as DeviceTokenRecord["platform"],
      installationId,
      publicKey,
    });
    await enqueueAction(DEVICE_TOKEN_REGISTER_ACTION, {
      publicKey,
      pushToken: token,
      installationId,
    });
    return { status: "queued", reason: "offline" };
  }

  try {
    await registerWithBackoff({ publicKey, pushToken: token, installationId });
    await persistTokenRecord({
      token,
      platform: Platform.OS as DeviceTokenRecord["platform"],
      installationId,
      publicKey,
    });
    return { status: "registered", token, alreadyRegistered: false };
  } catch (error) {
    const reason =
      error instanceof Error
        ? error.message
        : "Device token registration failed";

    // Persist the token locally even on failure so we can retry on the
    // next foreground / reconnect without having to re-prompt the user.
    await persistTokenRecord({
      token,
      platform: Platform.OS as DeviceTokenRecord["platform"],
      installationId,
      publicKey,
    });
    await enqueueAction(DEVICE_TOKEN_REGISTER_ACTION, {
      publicKey,
      pushToken: token,
      installationId,
    });
    await reportRegistrationFailure(reason, "request-failed");
    return { status: "queued", reason: "request-failed" };
  }
}

/**
 * Performs the actual POST with exponential backoff. Resolves on first 2xx
 * or throws on the final attempt.
 */
export async function registerWithBackoff(args: {
  publicKey: string;
  pushToken: string;
  installationId: string;
}): Promise<void> {
  let lastError: Error | null = null;
  for (let attempt = 0; attempt < REGISTRATION_MAX_ATTEMPTS; attempt += 1) {
    try {
      await postDeviceTokenToBackend(args);
      return;
    } catch (error) {
      lastError =
        error instanceof Error ? error : new Error("Unknown registration error");
      if (attempt === REGISTRATION_MAX_ATTEMPTS - 1) break;
      const delay = REGISTRATION_BACKOFF_MS[attempt] ?? 60_000;
      await sleep(delay);
    }
  }
  throw lastError ?? new Error("Device token registration failed");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function persistTokenRecord(args: {
  token: string;
  platform: DeviceTokenRecord["platform"];
  installationId: string;
  publicKey: string;
}): Promise<void> {
  const record: DeviceTokenRecord = {
    token: args.token,
    platform: args.platform,
    installationId: args.installationId,
    publicKey: args.publicKey,
    registeredAt: Date.now(),
  };
  await writeJson(STORAGE_KEYS.token, record);
  await AsyncStorage.setItem(STORAGE_KEYS.installationId, args.installationId);
  await AsyncStorage.setItem(STORAGE_KEYS.publicKey, args.publicKey);
  await AsyncStorage.setItem(STORAGE_KEYS.registeredAt, String(record.registeredAt));
}

async function reportRegistrationFailure(
  reason: string,
  kind: "request-failed" | "permission-revoked",
): Promise<void> {
  try {
    const error = new Error(
      `Device token registration (${kind}): ${reason}`,
    );
    if (kind === "request-failed") {
      await captureNativeCrash(error);
    } else {
      await captureUnhandledError(error, "Device token registration");
    }
  } catch {
    // Crash reporting should never block the registration flow.
  }
}

// ---------------------------------------------------------------------------
// Public API — deregistration
// ---------------------------------------------------------------------------

/**
 * Best-effort deregistration. Called on sign-out so the backend stops
 * pushing to this device.
 *
 * The local record is always wiped, even if the backend call fails, so a
 * future sign-in starts from a clean slate.
 */
export async function deregisterDeviceToken(args: {
  publicKey: string | null | undefined;
}): Promise<DeregisterResult> {
  registerDeviceTokenQueueHandlers();

  if (Platform.OS === "web") {
    await clearStoredDeviceToken();
    return { status: "skipped", reason: "web-platform" };
  }

  const publicKey = args.publicKey ?? (await getStoredPublicKey());
  if (!publicKey) {
    await clearStoredDeviceToken();
    return { status: "skipped", reason: "no-wallet" };
  }

  const installationId = await getOrCreateInstallationId();

  if (!(await isOnline())) {
    await clearStoredDeviceToken();
    await enqueueAction(DEVICE_TOKEN_DEREGISTER_ACTION, {
      publicKey,
      installationId,
    });
    return { status: "queued", reason: "offline" };
  }

  try {
    await postDeregisterToBackend({ publicKey, installationId });
    await clearStoredDeviceToken();
    return { status: "deregistered" };
  } catch (error) {
    const reason =
      error instanceof Error ? error.message : "Unknown deregister error";
    await clearStoredDeviceToken();
    await enqueueAction(DEVICE_TOKEN_DEREGISTER_ACTION, {
      publicKey,
      installationId,
    });
    await reportRegistrationFailure(reason, "request-failed");
    return { status: "queued", reason: "request-failed" };
  }
}

// ---------------------------------------------------------------------------
// Public API — permission transitions & supersession
// ---------------------------------------------------------------------------

/**
 * Called when the user revokes notification permission. Drops the stored
 * record so the next grant starts clean. The installation id is kept so a
 * later re-grant can re-bind the *same logical install* without us
 * incorrectly treating it as a fresh install.
 */
export async function handlePermissionRevoked(): Promise<void> {
  await Promise.all(
    [
      STORAGE_KEYS.token,
      STORAGE_KEYS.publicKey,
      STORAGE_KEYS.registeredAt,
    ].map((key) => AsyncStorage.removeItem(key)),
  );
}

/**
 * Detects reinstalls and device restores by comparing the persisted
 * installation id against the live one. If they differ, the previous
 * registration is superseded (delete-old + register-new) so a single
 * wallet only has one active device-token record.
 */
export async function reconcileInstallation(args: {
  publicKey: string | null | undefined;
}): Promise<
  | { status: "unchanged" }
  | { status: "superseded"; previousPublicKey?: string }
  | { status: "skipped"; reason: "no-stored-record" }
> {
  const stored = await getStoredDeviceToken();
  if (!stored) {
    return { status: "skipped", reason: "no-stored-record" };
  }

  const liveInstallationId = await getOrCreateInstallationId();
  if (stored.installationId === liveInstallationId) {
    return { status: "unchanged" };
  }

  // Persisted id is stale — this device was reinstalled or restored from a
  // backup. Drop the old token, then re-register against the new one.
  const previousPublicKey = stored.publicKey;
  await clearStoredDeviceToken();

  if (previousPublicKey && !args.publicKey) {
    // We have no live session, so just delete the orphaned record on the
    // backend and stop. The next sign-in will re-register.
    if (await isOnline()) {
      try {
        await postDeregisterToBackend({
          publicKey: previousPublicKey,
          installationId: liveInstallationId,
        });
      } catch {
        // Best-effort; a stale row will eventually be reaped server-side.
      }
    } else {
      await enqueueAction(DEVICE_TOKEN_DEREGISTER_ACTION, {
        publicKey: previousPublicKey,
        installationId: liveInstallationId,
      });
    }
  }

  return { status: "superseded", previousPublicKey };
}

// ---------------------------------------------------------------------------
// Flush helper
// ---------------------------------------------------------------------------

/**
 * Flushes any queued device-token retries. Call on reconnect / foreground.
 */
export async function flushDeviceTokenQueue(): Promise<void> {
  registerDeviceTokenQueueHandlers();
  await processOfflineQueue();
}
