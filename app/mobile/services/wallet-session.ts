import AsyncStorage from "@react-native-async-storage/async-storage";
import type { StellarNetwork, WalletType } from "../types/wallet";

export type WalletNetwork = StellarNetwork;

export interface WalletSession {
  publicKey: string;
  network: WalletNetwork;
  walletType: WalletType;
  connectedAt: number;
  /** ISO-8601 timestamp when the session was last confirmed active */
  lastConfirmedAt: string;
  /** Environment the session was created in (production/staging/testnet/branch-preview) */
  environmentId?: string;
  /** Build tag from when the session was created */
  buildTag?: string;
}

/**
 * Reason a session was deemed invalid and could not be restored.
 */
export type SessionInvalidReason =
  | "expired"
  | "environment_mismatch"
  | "corrupted"
  | "none";

const WALLET_SESSION_KEY = "quickex.wallet.session.v3";
const LAST_WALLET_TYPE_KEY = "quickex.wallet.lastType";

/**
 * Maximum age for a session to be considered restorable (7 days).
 * After this the user must re-connect explicitly.
 */
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

// ── Helpers ──────────────────────────────────────────────────────────────────

function isValidWalletType(value: unknown): value is WalletType {
  return (
    typeof value === "string" &&
    ["freighter", "lobstr", "xbull", "albedo", "demo"].includes(value)
  );
}

function isValidNetwork(value: unknown): value is WalletNetwork {
  return value === "testnet" || value === "mainnet";
}

// ── Session CRUD ─────────────────────────────────────────────────────────────

export async function getWalletSession(): Promise<WalletSession | null> {
  try {
    const raw = await AsyncStorage.getItem(WALLET_SESSION_KEY);
    if (!raw) return null;

    const parsed = JSON.parse(raw) as Partial<WalletSession>;

    if (
      !parsed.publicKey ||
      !isValidNetwork(parsed.network) ||
      !isValidWalletType(parsed.walletType) ||
      !parsed.connectedAt
    ) {
      // Corrupted session – clear it so the user starts fresh
      await clearWalletSession();
      return null;
    }

    return {
      publicKey: parsed.publicKey,
      network: parsed.network,
      walletType: parsed.walletType,
      connectedAt: parsed.connectedAt,
      lastConfirmedAt: parsed.lastConfirmedAt ?? new Date(parsed.connectedAt).toISOString(),
      environmentId: parsed.environmentId,
      buildTag: parsed.buildTag,
    };
  } catch {
    return null;
  }
}

export async function saveWalletSession(
  session: WalletSession,
  environmentId?: string,
  buildTag?: string,
): Promise<void> {
  const enriched: WalletSession = {
    ...session,
    environmentId: environmentId ?? session.environmentId,
    buildTag: buildTag ?? session.buildTag,
  };
  await AsyncStorage.setItem(WALLET_SESSION_KEY, JSON.stringify(enriched));
  await AsyncStorage.setItem(LAST_WALLET_TYPE_KEY, session.walletType);
}

export async function clearWalletSession(): Promise<void> {
  await AsyncStorage.removeItem(WALLET_SESSION_KEY);
}

/**
 * Safely resets an invalid session and returns the reason.
 * Unlike direct clear, this preserves diagnostic information so the UI
 * can explain to the user why their session was reset.
 */
export async function resetInvalidSession(
  currentEnvironmentId?: string,
): Promise<{ reason: SessionInvalidReason; session?: WalletSession }> {
  const session = await getWalletSession();
  if (!session) return { reason: "corrupted" };

  const result = getSessionInvalidReason(session, currentEnvironmentId);
  if (!result.invalid) return { reason: "none", session };

  await clearWalletSession();
  return { reason: result.reason, session };
}

// ── Session Validation ───────────────────────────────────────────────────────

/**
 * Returns `true` when the stored session is within the max-age window and
 * safe to restore automatically.
 */
export function isSessionRestorable(session: WalletSession): boolean {
  const now = Date.now();
  const age = now - session.connectedAt;

  if (age > SESSION_MAX_AGE_MS) return false;

  // Also check the last-confirmed timestamp – if it's stale the user might
  // have changed wallets externally.
  try {
    const lastConfirmed = new Date(session.lastConfirmedAt).getTime();
    if (Number.isNaN(lastConfirmed)) return false;
    if (now - lastConfirmed > SESSION_MAX_AGE_MS) return false;
  } catch {
    return false;
  }

  return true;
}

/**
 * Returns the reason a session is invalid, or `"none"` if it is restorable.
 * This is more detailed than `isSessionRestorable` so the UI can surface
 * specific recovery instructions.
 */
export function getSessionInvalidReason(
  session: WalletSession | null,
  currentEnvironmentId?: string,
): { invalid: false } | { invalid: true; reason: SessionInvalidReason } {
  if (!session) return { invalid: true, reason: "corrupted" };

  const now = Date.now();
  const age = now - session.connectedAt;

  if (age > SESSION_MAX_AGE_MS) return { invalid: true, reason: "expired" };

  try {
    const lastConfirmed = new Date(session.lastConfirmedAt).getTime();
    if (Number.isNaN(lastConfirmed)) return { invalid: true, reason: "corrupted" };
    if (now - lastConfirmed > SESSION_MAX_AGE_MS) return { invalid: true, reason: "expired" };
  } catch {
    return { invalid: true, reason: "corrupted" };
  }

  if (
    currentEnvironmentId &&
    session.environmentId &&
    session.environmentId !== currentEnvironmentId
  ) {
    return { invalid: true, reason: "environment_mismatch" };
  }

  return { invalid: false };
}

/**
 * Checks whether the session was created in a different environment/branch
 * than the app is currently running in.
 */
export function isSessionEnvironmentMismatch(
  session: WalletSession,
  currentEnvironmentId: string,
): boolean {
  if (!session.environmentId) return false;
  return session.environmentId !== currentEnvironmentId;
}

/**
 * Call after a successful wallet interaction to bump the last-confirmed
 * timestamp, keeping the session alive.
 */
export async function touchSession(): Promise<void> {
  const session = await getWalletSession();
  if (!session) return;

  session.lastConfirmedAt = new Date().toISOString();
  await saveWalletSession(session);
}

// ── Last Wallet Type ─────────────────────────────────────────────────────────

export async function getLastWalletType(): Promise<WalletType | null> {
  try {
    const raw = await AsyncStorage.getItem(LAST_WALLET_TYPE_KEY);
    if (!raw) return null;
    return isValidWalletType(raw) ? raw : null;
  } catch {
    return null;
  }
}
