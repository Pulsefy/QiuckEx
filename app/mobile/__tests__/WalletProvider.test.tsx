/**
 * Integration tests for the WalletContext / WalletProvider.
 *
 * Covers: connect, disconnect, switchAccount, switchNetwork, session restore,
 * edge-case error handling (wallet_locked, wrong_network, signature_rejected).
 */
import React from "react";
import renderer, { act } from "react-test-renderer";
import { Text } from "react-native";

import { WalletProvider, useWalletContext } from "../hooks/useWalletContext";
import type { WalletContextValue, WalletType } from "../types/wallet";

// ── Mocks ────────────────────────────────────────────────────────────────────

jest.mock("../services/wallet-session", () => {
  let storedSession: any = null;
  let lastWalletType: string | null = null;

  return {
    getWalletSession: jest.fn(async () => storedSession),
    saveWalletSession: jest.fn(async (session: any) => {
      storedSession = session;
      lastWalletType = session.walletType;
    }),
    clearWalletSession: jest.fn(async () => {
      storedSession = null;
    }),
    isSessionRestorable: jest.fn((session: any) => {
      if (!session) return false;
      const age = Date.now() - session.connectedAt;
      return age < 7 * 24 * 60 * 60 * 1000;
    }),
    touchSession: jest.fn(async () => {}),
    getLastWalletType: jest.fn(async () => lastWalletType),
  };
});

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

// ── Test harness ─────────────────────────────────────────────────────────────

let capturedWallet: WalletContextValue | null = null;

function Harness() {
  capturedWallet = useWalletContext();
  return <Text>test</Text>;
}

function renderWithProvider() {
  capturedWallet = null;
  return renderer.create(
    <WalletProvider>
      <Harness />
    </WalletProvider>,
  );
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("WalletProvider", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
    const sessionMod = jest.requireMock("../services/wallet-session");
    sessionMod.getWalletSession.mockResolvedValue(null);
    sessionMod.getLastWalletType.mockResolvedValue(null);
  });

  describe("initial state / session restore", () => {
    it("starts restoring and then settles to disconnected", async () => {
      const tree = renderWithProvider();

      // Wait for hydration
      await act(async () => {});

      expect(capturedWallet).not.toBeNull();
      expect(capturedWallet!.wallet.connected).toBe(false);
      expect(capturedWallet!.wallet.isRestoring).toBe(false);
      expect(capturedWallet!.wallet.publicKey).toBeUndefined();

      tree.unmount();
    });

    it("restores a valid saved session on mount", async () => {
      const sessionMod = jest.requireMock("../services/wallet-session");
      const mockSession = {
        publicKey: "GARESTOREDEMOCKEY000000000000000000000000000",
        network: "testnet",
        walletType: "freighter",
        connectedAt: Date.now(),
        lastConfirmedAt: new Date().toISOString(),
      };
      sessionMod.getWalletSession.mockResolvedValue(mockSession);
      sessionMod.isSessionRestorable.mockReturnValue(true);

      const tree = renderWithProvider();

      await act(async () => {});

      expect(capturedWallet!.wallet.connected).toBe(true);
      expect(capturedWallet!.wallet.publicKey).toBe(mockSession.publicKey);
      expect(capturedWallet!.wallet.walletType).toBe("freighter");
      expect(capturedWallet!.wallet.network).toBe("testnet");

      tree.unmount();
    });

    it("does not restore an expired session", async () => {
      const sessionMod = jest.requireMock("../services/wallet-session");
      const expiredSession = {
        publicKey: "GAEXPIREDMOCKEY0000000000000000000000000000000",
        network: "testnet",
        walletType: "demo",
        connectedAt: Date.now() - 8 * 24 * 60 * 60 * 1000,
        lastConfirmedAt: new Date(
          Date.now() - 8 * 24 * 60 * 60 * 1000,
        ).toISOString(),
      };
      sessionMod.getWalletSession.mockResolvedValue(expiredSession);
      sessionMod.isSessionRestorable.mockReturnValue(false);

      const tree = renderWithProvider();

      await act(async () => {});

      expect(capturedWallet!.wallet.connected).toBe(false);
      expect(capturedWallet!.wallet.error?.code).toBe("session_expired");

      tree.unmount();
    });
  });

  describe("connect", () => {
    it("connects with the demo wallet type", async () => {
      const tree = renderWithProvider();

      await act(async () => {});

      await act(async () => {
        await capturedWallet!.connect("demo", "testnet");
      });

      expect(capturedWallet!.wallet.connected).toBe(true);
      expect(capturedWallet!.wallet.walletType).toBe("demo");
      expect(capturedWallet!.wallet.publicKey).toBeTruthy();
      expect(capturedWallet!.wallet.error).toBeUndefined();

      tree.unmount();
    });

    it("saves session on connect", async () => {
      const sessionMod = jest.requireMock("../services/wallet-session");
      const tree = renderWithProvider();

      await act(async () => {});

      await act(async () => {
        await capturedWallet!.connect("demo", "testnet");
      });

      expect(sessionMod.saveWalletSession).toHaveBeenCalledTimes(1);
      const savedSession = sessionMod.saveWalletSession.mock.calls[0][0];
      expect(savedSession.walletType).toBe("demo");
      expect(savedSession.network).toBe("testnet");

      tree.unmount();
    });

    it("sets error on wallet_locked edge case", async () => {
      const randomSpy = jest.spyOn(Math, "random").mockReturnValue(0.01);

      const tree = renderWithProvider();

      await act(async () => {});

      await act(async () => {
        await capturedWallet!.connect("freighter", "testnet");
      });

      expect(capturedWallet!.wallet.connected).toBe(false);
      expect(capturedWallet!.wallet.error?.code).toBe("wallet_locked");
      expect(capturedWallet!.wallet.error?.recoverable).toBe(true);

      randomSpy.mockRestore();
      tree.unmount();
    });

    it("sets error on wrong_network edge case", async () => {
      const randomSpy = jest
        .spyOn(Math, "random")
        .mockReturnValueOnce(0.5) // not locked
        .mockReturnValueOnce(0.01); // wrong network

      const tree = renderWithProvider();

      await act(async () => {});

      await act(async () => {
        await capturedWallet!.connect("freighter", "mainnet");
      });

      expect(capturedWallet!.wallet.connected).toBe(false);
      expect(capturedWallet!.wallet.error?.code).toBe("wrong_network");

      randomSpy.mockRestore();
      tree.unmount();
    });

    it("sets error on signature_rejected edge case", async () => {
      // rand < 0.05 → not locked, rand < 0.10 → not wrong network,
      // rand < 0.15 → signature rejected
      const randomSpy = jest
        .spyOn(Math, "random")
        .mockReturnValue(0.12);

      const tree = renderWithProvider();

      await act(async () => {});

      await act(async () => {
        await capturedWallet!.connect("lobstr", "testnet");
      });

      expect(capturedWallet!.wallet.connected).toBe(false);
      expect(capturedWallet!.wallet.error?.code).toBe("signature_rejected");
      expect(capturedWallet!.wallet.error?.recoverable).toBe(true);

      randomSpy.mockRestore();
      tree.unmount();
    });
  });

  describe("disconnect", () => {
    it("disconnects a connected wallet", async () => {
      const sessionMod = jest.requireMock("../services/wallet-session");
      const tree = renderWithProvider();

      await act(async () => {});

      // Connect first
      await act(async () => {
        await capturedWallet!.connect("demo", "testnet");
      });

      expect(capturedWallet!.wallet.connected).toBe(true);

      // Now disconnect
      await act(async () => {
        await capturedWallet!.disconnect();
      });

      expect(capturedWallet!.wallet.connected).toBe(false);
      expect(capturedWallet!.wallet.publicKey).toBeUndefined();
      expect(sessionMod.clearWalletSession).toHaveBeenCalled();

      tree.unmount();
    });

    it("preserves network after disconnect", async () => {
      const tree = renderWithProvider();

      await act(async () => {});

      await act(async () => {
        await capturedWallet!.connect("freighter", "mainnet");
      });

      await act(async () => {
        await capturedWallet!.disconnect();
      });

      expect(capturedWallet!.wallet.network).toBe("mainnet");

      tree.unmount();
    });
  });

  describe("switchAccount", () => {
    it("switches the active public key", async () => {
      const sessionMod = jest.requireMock("../services/wallet-session");
      const tree = renderWithProvider();

      await act(async () => {});

      await act(async () => {
        await capturedWallet!.connect("demo", "testnet");
      });

      const newKey =
        "GANEWACCOUNTKEY00000000000000000000000000000000000";

      await act(async () => {
        await capturedWallet!.switchAccount(newKey);
      });

      expect(capturedWallet!.wallet.publicKey).toBe(newKey);

      // Should save the updated session
      const lastCall =
        sessionMod.saveWalletSession.mock.calls[
          sessionMod.saveWalletSession.mock.calls.length - 1
        ];
      expect(lastCall[0].publicKey).toBe(newKey);

      tree.unmount();
    });

    it("does nothing when not connected", async () => {
      const tree = renderWithProvider();

      await act(async () => {});

      await act(async () => {
        await capturedWallet!.switchAccount("GASOMEKEY");
      });

      expect(capturedWallet!.wallet.connected).toBe(false);

      tree.unmount();
    });
  });

  describe("switchNetwork", () => {
    it("switches the network", async () => {
      const tree = renderWithProvider();

      await act(async () => {});

      expect(capturedWallet!.wallet.network).toBe("testnet");

      act(() => {
        capturedWallet!.switchNetwork("mainnet");
      });

      expect(capturedWallet!.wallet.network).toBe("mainnet");

      tree.unmount();
    });
  });

  describe("clearError", () => {
    it("clears the current error", async () => {
      const randomSpy = jest.spyOn(Math, "random").mockReturnValue(0.01);

      const tree = renderWithProvider();

      await act(async () => {});

      await act(async () => {
        await capturedWallet!.connect("freighter", "testnet");
      });

      expect(capturedWallet!.wallet.error).toBeDefined();

      act(() => {
        capturedWallet!.clearError();
      });

      expect(capturedWallet!.wallet.error).toBeUndefined();

      randomSpy.mockRestore();
      tree.unmount();
    });
  });
});
