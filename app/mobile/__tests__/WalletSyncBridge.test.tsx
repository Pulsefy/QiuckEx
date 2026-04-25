/**
 * Integration test for WalletSyncBridge — verifies that notification
 * re-sync is triggered when the wallet public key changes.
 */
import React from "react";
import renderer, { act } from "react-test-renderer";
import { Text } from "react-native";

import { WalletProvider, useWalletContext } from "../hooks/useWalletContext";
import { WalletSyncBridge } from "../components/wallet/WalletSyncBridge";

// ── Mocks ────────────────────────────────────────────────────────────────────

jest.mock("../services/wallet-session", () => ({
  getWalletSession: jest.fn(async () => null),
  saveWalletSession: jest.fn(async () => {}),
  clearWalletSession: jest.fn(async () => {}),
  isSessionRestorable: jest.fn(() => false),
  touchSession: jest.fn(async () => {}),
  getLastWalletType: jest.fn(async () => null),
}));

jest.mock("../hooks/use-security", () => ({
  useSecurity: () => ({
    saveSensitiveSessionToken: jest.fn(async () => {}),
    clearSensitiveSessionToken: jest.fn(async () => {}),
    getSensitiveSessionToken: jest.fn(async () => null),
    authenticateForSensitiveAction: jest.fn(async () => true),
    isReady: true,
    isAppLocked: false,
    isBiometricAvailable: true,
    hasPinConfigured: false,
    settings: { biometricLockEnabled: false },
    setBiometricLockEnabled: jest.fn(async () => ({ ok: true })),
    savePin: jest.fn(async () => ({ ok: true })),
    unlockApp: jest.fn(async () => true),
  }),
  SecurityProvider: ({ children }: { children: React.ReactNode }) => children,
}));

const mockSyncNow = jest.fn(async () => {});

jest.mock("../components/notifications/NotificationContext", () => ({
  useNotifications: () => ({
    syncNow: mockSyncNow,
    currentAccountId: null,
    notifications: [],
    recentActivity: [],
    unreadCount: 0,
    backgroundSyncSettings: { enabled: true, frequency: "balanced", wifiOnly: false, badgeEnabled: true },
    backgroundTaskAvailable: false,
    isHydrated: true,
    isSyncing: false,
    lastSyncedAt: null,
    addNotification: jest.fn(),
    markAllRead: jest.fn(),
    setBackgroundSyncSettings: jest.fn(async () => {}),
    soundEnabled: true,
    setSoundEnabled: jest.fn(),
  }),
  NotificationProvider: ({ children }: { children: React.ReactNode }) => children,
}));

// ── Test harness ─────────────────────────────────────────────────────────────

let capturedWallet: ReturnType<typeof useWalletContext> | null = null;

function Harness() {
  capturedWallet = useWalletContext();
  return <Text>test</Text>;
}

function renderWithBridge() {
  capturedWallet = null;
  return renderer.create(
    <WalletProvider>
      <Harness />
      <WalletSyncBridge />
    </WalletProvider>,
  );
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("WalletSyncBridge", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    const sessionMod = jest.requireMock("../services/wallet-session");
    sessionMod.getWalletSession.mockResolvedValue(null);
    sessionMod.getLastWalletType.mockResolvedValue(null);
  });

  it("triggers syncNow when wallet connects", async () => {
    const tree = renderWithBridge();

    await act(async () => {});

    // Initial mount triggers one sync (publicKey changes from undefined to a value)
    // But since wallet starts disconnected, publicKey is undefined both before and after mount
    // So no extra sync from the bridge on mount

    const initialCallCount = mockSyncNow.mock.calls.length;

    await act(async () => {
      await capturedWallet!.connect("demo", "testnet");
    });

    // After connecting, publicKey changes → bridge should trigger syncNow
    expect(mockSyncNow.mock.calls.length).toBeGreaterThan(initialCallCount);

    tree.unmount();
  });

  it("triggers syncNow when wallet disconnects", async () => {
    const tree = renderWithBridge();

    await act(async () => {});

    await act(async () => {
      await capturedWallet!.connect("demo", "testnet");
    });

    const callCountAfterConnect = mockSyncNow.mock.calls.length;

    await act(async () => {
      await capturedWallet!.disconnect();
    });

    // After disconnecting, publicKey goes back to undefined → bridge triggers syncNow
    expect(mockSyncNow.mock.calls.length).toBeGreaterThan(callCountAfterConnect);

    tree.unmount();
  });

  it("triggers syncNow when account switches", async () => {
    const tree = renderWithBridge();

    await act(async () => {});

    await act(async () => {
      await capturedWallet!.connect("demo", "testnet");
    });

    const callCountAfterConnect = mockSyncNow.mock.calls.length;

    await act(async () => {
      await capturedWallet!.switchAccount(
        "GANEWACCOUNTKEY00000000000000000000000000000000000",
      );
    });

    // After switching account, publicKey changes → bridge triggers syncNow
    expect(mockSyncNow.mock.calls.length).toBeGreaterThan(callCountAfterConnect);

    tree.unmount();
  });
});
