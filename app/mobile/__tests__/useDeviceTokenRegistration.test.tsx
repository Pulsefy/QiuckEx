/**
 * Hook-level tests for the device-token registration lifecycle.
 *
 * Verifies that the hook subscribes to the right native events and
 * reconciles correctly on lifecycle transitions. The actual service
 * behavior is covered exhaustively in `device-token-registration.test.ts`;
 * here we focus on the React glue (effect ordering, AppState, NetInfo,
 * push-token refresh) that the pure service tests cannot reach.
 */
import React from "react";
import renderer, { act } from "react-test-renderer";

import { useDeviceTokenRegistration } from "../hooks/useDeviceTokenRegistration";

// ── Mocks ────────────────────────────────────────────────────────────────────

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
    addEventListener: jest.fn((cb: any) => {
      listener = cb;
      return () => {
        listener = null;
      };
    }),
    __emit: (value: boolean) => {
      isConnected = value;
      if (listener) listener({ isConnected: value, isInternetReachable: value });
    },
  };
});

jest.mock("expo-constants", () => ({ isDevice: true }));

const mockPushTokenListeners = new Set<(value: { data: string }) => void>();
jest.mock("expo-notifications", () => ({
  getPermissionsAsync: jest.fn(async () => ({
    granted: true,
    status: "granted",
    canAskAgain: true,
  })),
  requestPermissionsAsync: jest.fn(async () => ({
    granted: true,
    status: "granted",
    canAskAgain: true,
  })),
  getExpoPushTokenAsync: jest.fn(async () => ({ data: "ExpoPushToken[test]" })),
  addPushTokenListener: jest.fn((listener: any) => {
    mockPushTokenListeners.add(listener);
    return { remove: () => mockPushTokenListeners.delete(listener) };
  }),
}));

jest.mock("../services/crash-monitoring", () => ({
  captureUnhandledError: jest.fn(async () => undefined),
  captureNativeCrash: jest.fn(async () => undefined),
}));

const mockGetWalletSession = jest.fn();
jest.mock("../services/wallet-session", () => ({
  getWalletSession: () => mockGetWalletSession(),
}));

// AppState is mocked via the `react-native` module below. We capture the
// list of subscribers so the test body can fire "change" events to drive
// the foreground reconcile path.
const mockAppStateListeners = new Set<(state: string) => void>();
jest.mock("react-native", () => {
  return {
    Platform: { OS: "ios" },
    AppState: {
      addEventListener: jest.fn((event: string, cb: any) => {
        if (event === "change") {
          mockAppStateListeners.add(cb);
          return { remove: () => mockAppStateListeners.delete(cb) };
        }
        return { remove: () => undefined };
      }),
    },
    __emitAppState: (next: string) => {
      for (const l of mockAppStateListeners) l(next);
    },
  };
});

const mockReconcileInstallation = jest.fn();
const mockRegisterDeviceToken = jest.fn();
const mockDeregisterDeviceToken = jest.fn();
const mockHandlePermissionRevoked = jest.fn();
const mockFlushDeviceTokenQueue = jest.fn();
const mockGetPermissionStatus = jest.fn();

jest.mock("../services/device-token-registration", () => {
  const actual = jest.requireActual("../services/device-token-registration");
  return {
    ...actual,
    reconcileInstallation: (...args: any[]) => mockReconcileInstallation(...args),
    registerDeviceToken: (...args: any[]) => mockRegisterDeviceToken(...args),
    deregisterDeviceToken: (...args: any[]) => mockDeregisterDeviceToken(...args),
    handlePermissionRevoked: () => mockHandlePermissionRevoked(),
    flushDeviceTokenQueue: () => mockFlushDeviceTokenQueue(),
    getPermissionStatus: () => mockGetPermissionStatus(),
    registerDeviceTokenQueueHandlers: jest.fn(),
    getNotificationsModule: () => {
      try {
        return require("expo-notifications");
      } catch {
        return null;
      }
    },
  };
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function Harness() {
  useDeviceTokenRegistration();
  return null;
}

function renderHook() {
  return renderer.create(<Harness />);
}

beforeEach(() => {
  jest.clearAllMocks();
  mockPushTokenListeners.clear();
  mockAppStateListeners.clear();
  // Re-seed mocks with async defaults — jest.clearAllMocks() also clears
  // mock implementations, so without this the hooks would call into
  // functions that return undefined.
  mockGetWalletSession.mockResolvedValue(null);
  mockReconcileInstallation.mockResolvedValue({ status: "unchanged" });
  mockRegisterDeviceToken.mockResolvedValue({
    status: "registered",
    token: "tok",
    alreadyRegistered: false,
  });
  mockDeregisterDeviceToken.mockResolvedValue({ status: "deregistered" });
  mockHandlePermissionRevoked.mockResolvedValue(undefined);
  mockFlushDeviceTokenQueue.mockResolvedValue(undefined);
  mockGetPermissionStatus.mockResolvedValue("granted");
});

// ── Tests ────────────────────────────────────────────────────────────────────

describe("useDeviceTokenRegistration lifecycle", () => {
  it("calls reconcileInstallation on mount to detect reinstall/restore", async () => {
    await act(async () => {
      renderHook();
    });
    await act(async () => {});

    expect(mockReconcileInstallation).toHaveBeenCalledTimes(1);
  });

  it("subscribes to expo-notifications push-token refresh events", async () => {
    const Notifications = require("expo-notifications");
    await act(async () => {
      renderHook();
    });

    expect(Notifications.addPushTokenListener).toHaveBeenCalledTimes(1);
  });

  it("subscribes to AppState change events for foreground reconcile", async () => {
    await act(async () => {
      renderHook();
    });
    expect(mockAppStateListeners.size).toBe(1);
  });

  it("subscribes to NetInfo for reconnect-driven queue flushes", async () => {
    const NetInfo = require("@react-native-community/netinfo");
    await act(async () => {
      renderHook();
    });
    expect(NetInfo.addEventListener).toHaveBeenCalled();
  });

  it("flushes the queue and refreshes the token when the app returns to foreground", async () => {
    mockGetWalletSession.mockResolvedValue({
      publicKey: "GABC",
      network: "testnet",
      walletType: "demo",
      connectedAt: Date.now(),
      lastConfirmedAt: new Date().toISOString(),
    });

    await act(async () => {
      renderHook();
    });
    await act(async () => {});

    mockFlushDeviceTokenQueue.mockClear();
    mockRegisterDeviceToken.mockClear();

    // Simulate app coming back to foreground
    const RN = require("react-native");
    await act(async () => {
      RN.__emitAppState("active");
    });
    await act(async () => {});

    expect(mockFlushDeviceTokenQueue).toHaveBeenCalled();
    // Permission is granted + wallet is connected, so a refresh should fire.
    expect(mockRegisterDeviceToken).toHaveBeenCalledWith({
      publicKey: "GABC",
    });
  });

  it("does not register on foreground when no wallet is connected", async () => {
    mockGetWalletSession.mockResolvedValue(null);

    await act(async () => {
      renderHook();
    });
    await act(async () => {});
    mockRegisterDeviceToken.mockClear();

    const RN = require("react-native");
    await act(async () => {
      RN.__emitAppState("active");
    });
    await act(async () => {});

    expect(mockRegisterDeviceToken).not.toHaveBeenCalled();
  });

  it("deregisters when permission flips from granted to denied on resume", async () => {
    mockGetWalletSession.mockResolvedValue({
      publicKey: "GABC",
      network: "testnet",
      walletType: "demo",
      connectedAt: Date.now(),
      lastConfirmedAt: new Date().toISOString(),
    });
    mockGetPermissionStatus
      .mockResolvedValueOnce("granted")
      .mockResolvedValueOnce("denied");

    await act(async () => {
      renderHook();
    });
    await act(async () => {});

    mockDeregisterDeviceToken.mockClear();
    mockHandlePermissionRevoked.mockClear();

    const RN = require("react-native");
    await act(async () => {
      RN.__emitAppState("active");
    });
    await act(async () => {});

    expect(mockHandlePermissionRevoked).toHaveBeenCalled();
    expect(mockDeregisterDeviceToken).toHaveBeenCalledWith({
      publicKey: "GABC",
    });
  });

  it("re-registers when the OS emits a push-token refresh event", async () => {
    mockGetWalletSession.mockResolvedValue({
      publicKey: "GABC",
      network: "testnet",
      walletType: "demo",
      connectedAt: Date.now(),
      lastConfirmedAt: new Date().toISOString(),
    });
    mockRegisterDeviceToken.mockResolvedValue({
      status: "registered",
      token: "new-tok",
      alreadyRegistered: false,
    });

    await act(async () => {
      renderHook();
    });
    await act(async () => {});

    mockRegisterDeviceToken.mockClear();

    await act(async () => {
      for (const listener of mockPushTokenListeners) {
        listener({ data: "new-push-token" });
      }
    });
    await act(async () => {});

    expect(mockRegisterDeviceToken).toHaveBeenCalledWith({
      publicKey: "GABC",
      force: true,
    });
  });

  it("clears local state when a token-refresh event reports permission denied", async () => {
    mockGetWalletSession.mockResolvedValue({
      publicKey: "GABC",
      network: "testnet",
      walletType: "demo",
      connectedAt: Date.now(),
      lastConfirmedAt: new Date().toISOString(),
    });
    mockRegisterDeviceToken.mockResolvedValue({
      status: "denied",
      reason: "denied",
    });

    await act(async () => {
      renderHook();
    });
    await act(async () => {});

    mockHandlePermissionRevoked.mockClear();

    await act(async () => {
      for (const listener of mockPushTokenListeners) {
        listener({ data: "new-push-token" });
      }
    });
    await act(async () => {});

    expect(mockHandlePermissionRevoked).toHaveBeenCalled();
  });

  it("flushes queued device-token retries on network reconnect", async () => {
    await act(async () => {
      renderHook();
    });
    await act(async () => {});
    mockFlushDeviceTokenQueue.mockClear();

    const NetInfo = require("@react-native-community/netinfo");
    await act(async () => {
      NetInfo.__emit(true);
    });

    expect(mockFlushDeviceTokenQueue).toHaveBeenCalled();
  });
});
