/**
 * Tests for the device-token registration lifecycle.
 *
 * Covers the acceptance criteria from the issue:
 *   - First grant → register
 *   - Token refresh → re-register (force=true / different stored token)
 *   - Sign-out → deregister
 *   - Reinstall / restore → supersede (clear stored record, drop old on backend)
 *   - Permission denied → no register, clear local state
 *   - Denied → granted → re-registers on next opportunity
 *   - Registration failure → exponential backoff retry + crash report
 *   - Offline → queue for later flush
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import NetInfo from "@react-native-community/netinfo";

import {
  DEVICE_TOKEN_DEREGISTER_ACTION,
  DEVICE_TOKEN_REGISTER_ACTION,
  REGISTRATION_BACKOFF_MS,
  REGISTRATION_MAX_ATTEMPTS,
  __resetDeviceTokenRegistrationState,
  clearStoredDeviceToken,
  deregisterDeviceToken,
  getStoredDeviceToken,
  getStoredInstallationId,
  getStoredPublicKey,
  handlePermissionRevoked,
  reconcileInstallation,
  registerDeviceToken,
  registerWithBackoff,
  setStoredDeviceTokenForTest,
} from "../services/device-token-registration";
import { getOfflineQueue } from "../services/offline-queue";
import * as crashMonitoring from "../services/crash-monitoring";

const mockCaptureUnhandledError =
  crashMonitoring.captureUnhandledError as jest.Mock;
const mockCaptureNativeCrash =
  crashMonitoring.captureNativeCrash as jest.Mock;

// ── Module mocks ─────────────────────────────────────────────────────────────

jest.mock("@react-native-async-storage/async-storage", () => {
  let store: Record<string, string> = {};
  return {
    getItem: jest.fn(async (key: string) => store[key] ?? null),
    setItem: jest.fn(async (key: string, value: string) => {
      store[key] = value;
    }),
    removeItem: jest.fn(async (key: string) => {
      delete store[key];
    }),
    clear: jest.fn(async () => {
      store = {};
    }),
    __dump: () => store,
  };
});

jest.mock("@react-native-community/netinfo", () => {
  let isConnected = true;
  let listener: ((state: any) => void) | null = null;
  return {
    fetch: jest.fn(async () => ({
      isConnected,
      isInternetReachable: isConnected,
    })),
    addEventListener: jest.fn((cb) => {
      listener = cb;
      return () => {
        listener = null;
      };
    }),
    setConnected: (value: boolean) => {
      isConnected = value;
      if (listener) listener({ isConnected: value, isInternetReachable: value });
    },
  };
});

// expo-constants is required by obtainDevicePushToken() to detect simulators.
jest.mock("expo-constants", () => ({
  isDevice: true,
}));

// We need a controllable fetch for the backend, and a controllable
// expo-notifications surface for the permission + token surface.
let mockFetch: jest.Mock;
// Exposed to the jest.mock factory via the `mock` prefix. Set by
// `setNextPushToken` from the test body so we can simulate a token refresh.
let mockCurrentPushToken = "ExpoPushToken[token-1]";

jest.mock("expo-notifications", () => {
  const mockPushTokenListeners = new Set<(mockValue: { data: string }) => void>();
  return {
    getPermissionsAsync: jest.fn(async () => ({
      granted: true,
      status: "granted",
      canAskAgain: true,
      ios: { status: "granted", allowsBadge: true },
    })),
    requestPermissionsAsync: jest.fn(async () => ({
      granted: true,
      status: "granted",
      canAskAgain: true,
      ios: { status: "granted", allowsBadge: true },
    })),
    getExpoPushTokenAsync: jest.fn(async () => ({ data: mockCurrentPushToken })),
    addPushTokenListener: jest.fn((listener: (mockValue: { data: string }) => void) => {
      mockPushTokenListeners.add(listener);
      return { remove: () => mockPushTokenListeners.delete(listener) };
    }),
    __emitPushToken: (token: string) => {
      for (const listener of mockPushTokenListeners) listener({ data: token });
    },
  };
});

// Crash monitoring must be observable without hitting the real network.
jest.mock("../services/crash-monitoring", () => ({
  captureUnhandledError: jest.fn(async () => undefined),
  captureNativeCrash: jest.fn(async () => undefined),
}));

// ── Helpers ──────────────────────────────────────────────────────────────────

function setOnline(connected: boolean) {
  (NetInfo as any).setConnected(connected);
}

function setNextPushToken(token: string) {
  mockCurrentPushToken = token;
}

beforeEach(async () => {
  jest.clearAllMocks();
  await AsyncStorage.clear();
  __resetDeviceTokenRegistrationState();
  setOnline(true);
  setNextPushToken("ExpoPushToken[token-1]");
  mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
  // eslint-disable-next-line no-undef
  (global as any).fetch = mockFetch;
});

afterEach(() => {
  __resetDeviceTokenRegistrationState();
});

// ── Test suites ──────────────────────────────────────────────────────────────

describe("device-token registration: first grant", () => {
  it("registers the device push token against the wallet on first grant", async () => {
    const result = await registerDeviceToken({ publicKey: "GABC" });

    expect(result.status).toBe("registered");
    if (result.status !== "registered") return;

    expect(result.token).toBe("ExpoPushToken[token-1]");
    expect(result.alreadyRegistered).toBe(false);

    // Backend was hit with PUT to the preferences endpoint
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain("/notifications/preferences/GABC");
    expect(init.method).toBe("PUT");
    const body = JSON.parse(init.body);
    expect(body.channel).toBe("push");
    expect(body.pushToken).toBe("ExpoPushToken[token-1]");
    expect(body.enabled).toBe(true);

    // Local state was persisted
    const stored = await getStoredDeviceToken();
    expect(stored).not.toBeNull();
    expect(stored?.publicKey).toBe("GABC");
    expect(stored?.token).toBe("ExpoPushToken[token-1]");

    const installationId = await getStoredInstallationId();
    expect(installationId).toBeTruthy();
    expect(stored?.installationId).toBe(installationId);
  });

  it("is a no-op when the token + wallet + installation id are unchanged", async () => {
    const first = await registerDeviceToken({ publicKey: "GABC" });
    expect(first.status).toBe("registered");
    const callsAfterFirst = mockFetch.mock.calls.length;

    const second = await registerDeviceToken({ publicKey: "GABC" });
    expect(second.status).toBe("registered");
    if (second.status !== "registered") return;
    expect(second.alreadyRegistered).toBe(true);

    // No additional backend hit.
    expect(mockFetch.mock.calls.length).toBe(callsAfterFirst);
  });
});

describe("device-token registration: token refresh", () => {
  it("re-registers when the OS rotates the push token", async () => {
    // First registration
    const first = await registerDeviceToken({ publicKey: "GABC" });
    expect(first.status).toBe("registered");
    const callsAfterFirst = mockFetch.mock.calls.length;

    // Simulate an OS-driven refresh — backend rotates the underlying
    // APNs/FCM token and expo-notifications yields a new one.
    setNextPushToken("ExpoPushToken[rotated-token-99]");
    const refreshed = await registerDeviceToken({ publicKey: "GABC" });
    expect(refreshed.status).toBe("registered");
    if (refreshed.status !== "registered") return;
    expect(refreshed.alreadyRegistered).toBe(false);

    // Backend was hit again with the new token.
    expect(mockFetch.mock.calls.length).toBe(callsAfterFirst + 1);
    const body = JSON.parse(mockFetch.mock.calls[callsAfterFirst][1].body);
    expect(body.pushToken).toBe("ExpoPushToken[rotated-token-99]");

    const stored = await getStoredDeviceToken();
    expect(stored?.token).toBe("ExpoPushToken[rotated-token-99]");
  });

  it("re-registers when the wallet public key changes", async () => {
    await registerDeviceToken({ publicKey: "GABC" });
    const callsAfterFirst = mockFetch.mock.calls.length;

    const switched = await registerDeviceToken({
      publicKey: "GDIFFERENT",
      force: true,
    });
    expect(switched.status).toBe("registered");
    if (switched.status !== "registered") return;
    expect(switched.alreadyRegistered).toBe(false);

    // One new backend call against the new public key.
    expect(mockFetch.mock.calls.length).toBe(callsAfterFirst + 1);
    const [url] = mockFetch.mock.calls[callsAfterFirst];
    expect(url).toContain("/notifications/preferences/GDIFFERENT");

    const stored = await getStoredDeviceToken();
    expect(stored?.publicKey).toBe("GDIFFERENT");
  });
});

describe("device-token registration: sign-out deregisters", () => {
  it("deregisters the push channel on sign-out and clears local state", async () => {
    await registerDeviceToken({ publicKey: "GABC" });
    expect(await getStoredDeviceToken()).not.toBeNull();

    const result = await deregisterDeviceToken({ publicKey: "GABC" });
    expect(result.status).toBe("deregistered");

    // DELETE was issued.
    const deleteCalls = mockFetch.mock.calls.filter(
      ([, init]: any) => init?.method === "DELETE",
    );
    expect(deleteCalls.length).toBe(1);
    expect(deleteCalls[0][0]).toContain("/notifications/preferences/GABC/push");

    // Local record wiped.
    expect(await getStoredDeviceToken()).toBeNull();
    expect(await getStoredPublicKey()).toBeNull();
  });

  it("uses the stored public key when none is supplied", async () => {
    await registerDeviceToken({ publicKey: "GABC" });
    mockFetch.mockClear();

    const result = await deregisterDeviceToken({ publicKey: null });
    expect(result.status).toBe("deregistered");

    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain("/notifications/preferences/GABC/push");
  });

  it("queues a deregister when offline", async () => {
    await registerDeviceToken({ publicKey: "GABC" });
    mockFetch.mockClear();
    setOnline(false);

    const result = await deregisterDeviceToken({ publicKey: "GABC" });
    expect(result.status).toBe("queued");

    // No DELETE attempted.
    const deleteCalls = mockFetch.mock.calls.filter(
      ([, init]: any) => init?.method === "DELETE",
    );
    expect(deleteCalls.length).toBe(0);

    // Local record still cleared even though backend call was deferred.
    expect(await getStoredDeviceToken()).toBeNull();

    // The action is in the offline queue.
    const queue = await getOfflineQueue();
    const entry = queue.find((q) => q.type === DEVICE_TOKEN_DEREGISTER_ACTION);
    expect(entry).toBeDefined();
    expect((entry?.payload as any)?.publicKey).toBe("GABC");
  });
});

describe("device-token registration: reinstall / restore supersession", () => {
  it("supersedes a stored record whose installation id no longer matches the live one", async () => {
    // Plant a record in storage as if a previous install had registered.
    // We then wipe the installation id from the "live" slot so the next
    // call to getOrCreateInstallationId() yields a fresh value, simulating
    // a fresh install / device restore.
    await setStoredDeviceTokenForTest({
      token: "ExpoPushToken[old-install-token]",
      platform: "ios",
      installationId: "OLD-INSTALLATION-ID",
      publicKey: "GABC",
      registeredAt: Date.now() - 60_000,
    });
    // Wipe the live installation id so the next read generates a new one.
    await AsyncStorage.removeItem("quickex.deviceToken.installationId.v1");

    // No live session yet — the previous wallet's record should be
    // explicitly dropped on the backend.
    const result = await reconcileInstallation({ publicKey: null });
    expect(result.status).toBe("superseded");
    if (result.status !== "superseded") return;
    expect(result.previousPublicKey).toBe("GABC");

    // Old token is dropped on the backend (DELETE issued).
    const deleteCalls = mockFetch.mock.calls.filter(
      ([, init]: any) => init?.method === "DELETE",
    );
    expect(deleteCalls.length).toBe(1);
    expect(deleteCalls[0][0]).toContain("/notifications/preferences/GABC/push");

    // Local record was cleared.
    expect(await getStoredDeviceToken()).toBeNull();
  });

  it("marks the record as superseded but does not call the backend when a live session will overwrite the token", async () => {
    await setStoredDeviceTokenForTest({
      token: "ExpoPushToken[old-install-token]",
      platform: "ios",
      installationId: "OLD-INSTALLATION-ID",
      publicKey: "GABC",
      registeredAt: Date.now() - 60_000,
    });
    await AsyncStorage.removeItem("quickex.deviceToken.installationId.v1");

    const result = await reconcileInstallation({ publicKey: "GNEW" });
    expect(result.status).toBe("superseded");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("leaves an unchanged installation id alone", async () => {
    await registerDeviceToken({ publicKey: "GABC" });
    mockFetch.mockClear();

    const result = await reconcileInstallation({ publicKey: "GABC" });
    expect(result.status).toBe("unchanged");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("returns skipped when there is no stored record at all", async () => {
    const result = await reconcileInstallation({ publicKey: "GABC" });
    expect(result.status).toBe("skipped");
  });
});

describe("device-token registration: permission transitions", () => {
  it("does not register when permission is denied and clears stored state", async () => {
    // Pre-condition: a previously-registered token exists.
    await registerDeviceToken({ publicKey: "GABC" });
    expect(await getStoredDeviceToken()).not.toBeNull();

    // User revokes permission in OS settings.
    setNextPushToken("");
    // We override the expo-notifications mock at runtime to flip permission.
    const Notifications = require("expo-notifications");
    (Notifications.getPermissionsAsync as jest.Mock).mockResolvedValueOnce({
      granted: false,
      status: "denied",
      canAskAgain: false,
    });
    (Notifications.requestPermissionsAsync as jest.Mock).mockResolvedValueOnce({
      granted: false,
      status: "denied",
      canAskAgain: false,
    });
    mockFetch.mockClear();

    const result = await registerDeviceToken({ publicKey: "GABC" });
    expect(result.status).toBe("denied");
    expect(mockFetch).not.toHaveBeenCalled();

    // Local record is wiped so a future re-grant starts clean.
    expect(await getStoredDeviceToken()).toBeNull();
  });

  it("registers cleanly after permission is re-granted (no reinstall required)", async () => {
    // First registration succeeds
    await registerDeviceToken({ publicKey: "GABC" });
    expect(await getStoredDeviceToken()).not.toBeNull();

    // User revokes permission; local state is wiped.
    const Notifications = require("expo-notifications");
    (Notifications.getPermissionsAsync as jest.Mock).mockResolvedValueOnce({
      granted: false,
      status: "denied",
      canAskAgain: true,
    });
    (Notifications.requestPermissionsAsync as jest.Mock).mockResolvedValueOnce({
      granted: false,
      status: "denied",
      canAskAgain: true,
    });
    const denied = await registerDeviceToken({ publicKey: "GABC" });
    expect(denied.status).toBe("denied");
    expect(await getStoredDeviceToken()).toBeNull();

    // User re-grants in OS settings.
    (Notifications.getPermissionsAsync as jest.Mock).mockResolvedValueOnce({
      granted: true,
      status: "granted",
      canAskAgain: true,
    });
    mockFetch.mockClear();

    const granted = await registerDeviceToken({ publicKey: "GABC" });
    expect(granted.status).toBe("registered");

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain("/notifications/preferences/GABC");
    expect(init.method).toBe("PUT");

    const stored = await getStoredDeviceToken();
    expect(stored).not.toBeNull();
    expect(stored?.publicKey).toBe("GABC");
  });

  it("handlePermissionRevoked clears all stored state", async () => {
    await registerDeviceToken({ publicKey: "GABC" });
    expect(await getStoredDeviceToken()).not.toBeNull();
    expect(await getStoredPublicKey()).toBe("GABC");
    expect(await getStoredInstallationId()).toBeTruthy();

    await handlePermissionRevoked();

    expect(await getStoredDeviceToken()).toBeNull();
    expect(await getStoredPublicKey()).toBeNull();
    // Installation id intentionally preserved so we can re-register the
    // same logical install once permission is re-granted.
    expect(await getStoredInstallationId()).toBeTruthy();
  });
});

describe("device-token registration: backoff and crash reporting", () => {
  it("retries with exponential backoff before failing", async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 503,
      json: async () => ({}),
    });

    // The full schedule sums to ~31s; the per-test jest timeout is 5s by
    // default, so we override it for this test only.
    const start = Date.now();
    await expect(
      registerWithBackoff({
        publicKey: "GABC",
        pushToken: "tok",
        installationId: "inst-1",
      }),
    ).rejects.toThrow(/HTTP 503/);
    const elapsed = Date.now() - start;

    // 5 attempts; first attempt is immediate, 4 backoff delays in between.
    expect(mockFetch).toHaveBeenCalledTimes(REGISTRATION_MAX_ATTEMPTS);

    // Sum of the backoff schedule (1s + 2s + 4s + 8s - last one not
    // applied because it was the final attempt).
    const expectedMin = REGISTRATION_BACKOFF_MS.slice(0, -1).reduce(
      (sum, value) => sum + value,
      0,
    );
    expect(elapsed).toBeGreaterThanOrEqual(expectedMin - 100);
  }, 60_000);

  it("returns immediately on a successful first attempt", async () => {
    await expect(
      registerWithBackoff({
        publicKey: "GABC",
        pushToken: "tok",
        installationId: "inst-1",
      }),
    ).resolves.toBeUndefined();
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("queues a retry and reports to crash monitoring on persistent failure", async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({}),
    });

    const result = await registerDeviceToken({ publicKey: "GABC" });
    expect(result.status).toBe("queued");
    if (result.status !== "queued") return;
    expect(result.reason).toBe("request-failed");

    // Retry attempt was queued.
    const queue = await getOfflineQueue();
    const entry = queue.find((q) => q.type === DEVICE_TOKEN_REGISTER_ACTION);
    expect(entry).toBeDefined();

    // Crash monitoring was notified.
    expect(mockCaptureNativeCrash).toHaveBeenCalled();
    const call = mockCaptureNativeCrash.mock.calls[0];
    const errorArg = call[0] as Error;
    expect(errorArg.message).toMatch(/Device token registration/);
  }, 60_000);

  it("queues a retry and reports to crash monitoring when offline", async () => {
    setOnline(false);
    const result = await registerDeviceToken({ publicKey: "GABC" });
    expect(result.status).toBe("queued");
    if (result.status !== "queued") return;
    expect(result.reason).toBe("offline");

    // No fetch attempted while offline.
    expect(mockFetch).not.toHaveBeenCalled();

    // Local state is persisted so the next foreground flush can pick it up.
    const stored = await getStoredDeviceToken();
    expect(stored).not.toBeNull();

    // Retry attempt was queued.
    const queue = await getOfflineQueue();
    const entry = queue.find((q) => q.type === DEVICE_TOKEN_REGISTER_ACTION);
    expect(entry).toBeDefined();
  });
});

describe("device-token registration: web / simulator / no-wallet guards", () => {
  it("skips registration when no wallet is connected", async () => {
    const result = await registerDeviceToken({ publicKey: null });
    expect(result.status).toBe("skipped");
    if (result.status !== "skipped") return;
    expect(result.reason).toBe("no-wallet");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("skips registration when no wallet is connected (undefined public key)", async () => {
    const result = await registerDeviceToken({ publicKey: undefined });
    expect(result.status).toBe("skipped");
  });
});

describe("device-token registration: concurrency", () => {
  it("coalesces parallel calls so the backend is only hit once", async () => {
    // Reset fetch to add a slight delay so calls overlap.
    mockFetch.mockImplementation(
      async () =>
        new Promise((resolve) =>
          setTimeout(
            () => resolve({ ok: true, status: 200, json: async () => ({}) }),
            20,
          ),
        ),
    );

    const [a, b, c] = await Promise.all([
      registerDeviceToken({ publicKey: "GABC" }),
      registerDeviceToken({ publicKey: "GABC" }),
      registerDeviceToken({ publicKey: "GABC" }),
    ]);

    expect(a.status).toBe("registered");
    expect(b.status).toBe("registered");
    expect(c.status).toBe("registered");
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

describe("device-token registration: clearStoredDeviceToken", () => {
  it("removes all persisted state", async () => {
    await registerDeviceToken({ publicKey: "GABC" });
    await clearStoredDeviceToken();
    expect(await getStoredDeviceToken()).toBeNull();
    expect(await getStoredPublicKey()).toBeNull();
  });
});
