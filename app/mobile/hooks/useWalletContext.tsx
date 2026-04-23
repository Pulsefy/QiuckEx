import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

import type {
  StellarNetwork,
  WalletContextValue,
  WalletError,
  WalletState,
  WalletType,
} from "../../types/wallet";
import {
  clearWalletSession,
  getLastWalletType,
  getWalletSession,
  isSessionRestorable,
  saveWalletSession,
  touchSession,
} from "../../services/wallet-session";
import { useSecurity } from "../use-security";

// ── Constants ────────────────────────────────────────────────────────────────

const DEMO_PUBLIC_KEY =
  "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP";

/** Available wallet options shown in the wallet picker UI */
export const SUPPORTED_WALLETS: Array<{
  type: WalletType;
  label: string;
  description: string;
}> = [
  {
    type: "freighter",
    label: "Freighter",
    description: "Browser extension by Stellar Development Foundation",
  },
  {
    type: "lobstr",
    label: "LOBSTR",
    description: "Mobile-first Stellar wallet",
  },
  {
    type: "xbull",
    label: "xBull",
    description: "Multi-network wallet with Stellar support",
  },
  {
    type: "albedo",
    label: "Albedo",
    description: "Session-based signing — no extension needed",
  },
  {
    type: "demo",
    label: "Demo Wallet",
    description: "Testnet demo account for quick exploration",
  },
];

// ── Error helpers ────────────────────────────────────────────────────────────

function walletError(
  code: WalletError["code"],
  message: string,
  recoverable = true,
): WalletError {
  return { code, message, recoverable };
}

// ── Context ──────────────────────────────────────────────────────────────────

const WalletContext = createContext<WalletContextValue | null>(null);

const INITIAL_STATE: WalletState = {
  connected: false,
  publicKey: undefined,
  network: "testnet",
  walletType: undefined,
  connectedAt: undefined,
  error: undefined,
  isRestoring: true, // true until first hydration completes
};

// ── Provider ─────────────────────────────────────────────────────────────────

export const WalletProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [wallet, setWallet] = useState<WalletState>(INITIAL_STATE);
  const { clearSensitiveSessionToken, saveSensitiveSessionToken } =
    useSecurity();

  // ── Session restore on mount ─────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false;

    async function restore() {
      try {
        const session = await getWalletSession();

        if (cancelled) return;

        if (session && isSessionRestorable(session)) {
          setWallet({
            connected: true,
            publicKey: session.publicKey,
            network: session.network,
            walletType: session.walletType,
            connectedAt: session.connectedAt,
            error: undefined,
            isRestoring: false,
          });

          // Bump the last-confirmed timestamp
          await touchSession();
        } else if (session && !isSessionRestorable(session)) {
          // Session expired — clear it silently
          await clearWalletSession();
          await clearSensitiveSessionToken();

          const lastType = await getLastWalletType();
          setWallet({
            ...INITIAL_STATE,
            isRestoring: false,
            walletType: lastType ?? undefined,
            error: walletError(
              "session_expired",
              "Your previous session has expired. Please reconnect your wallet.",
            ),
          });
        } else {
          // No prior session
          const lastType = await getLastWalletType();
          setWallet({
            ...INITIAL_STATE,
            isRestoring: false,
            walletType: lastType ?? undefined,
          });
        }
      } catch {
        if (!cancelled) {
          setWallet({ ...INITIAL_STATE, isRestoring: false });
        }
      }
    }

    restore();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Periodic session touch (every 15 min while connected) ────────────────

  useEffect(() => {
    if (!wallet.connected) return;

    const interval = setInterval(() => {
      touchSession().catch(() => {});
    }, 15 * 60 * 1000);

    return () => clearInterval(interval);
  }, [wallet.connected]);

  // ── Connect ──────────────────────────────────────────────────────────────

  const connect = useCallback(
    async (walletType: WalletType, network?: StellarNetwork) => {
      setWallet((prev) => ({ ...prev, error: undefined }));

      try {
        // In a real integration each branch would invoke the wallet SDK.
        // For now we simulate the common failure modes + happy path.
        const selectedNetwork = network ?? wallet.network ?? "testnet";

        // ── Edge-case simulation (real SDKs will throw these naturally) ────
        if (walletType !== "demo") {
          const rand = Math.random();

          // Simulate: ~5 % chance the wallet is locked
          if (rand < 0.05) {
            throw walletError(
              "wallet_locked",
              "Your wallet is locked. Please unlock it and try again.",
            );
          }

          // Simulate: ~5 % chance the wallet is on the wrong network
          if (rand < 0.10) {
            throw walletError(
              "wrong_network",
              `Your wallet is not on ${selectedNetwork}. Switch your wallet network and try again.`,
            );
          }

          // Simulate: ~5 % chance the user rejects the signature request
          if (rand < 0.15) {
            throw walletError(
              "signature_rejected",
              "You rejected the signature request. Please try again and approve the transaction.",
            );
          }
        }

        const publicKey =
          walletType === "demo" ? DEMO_PUBLIC_KEY : DEMO_PUBLIC_KEY; // TODO: real key from SDK

        const now = Date.now();

        await saveWalletSession({
          publicKey,
          network: selectedNetwork,
          walletType,
          connectedAt: now,
          lastConfirmedAt: new Date(now).toISOString(),
        });

        await saveSensitiveSessionToken(
          `qex_session_${Math.random().toString(36).slice(2, 14)}`,
        );

        setWallet({
          connected: true,
          publicKey,
          network: selectedNetwork,
          walletType,
          connectedAt: now,
          error: undefined,
          isRestoring: false,
        });
      } catch (err) {
        const error: WalletError =
          err && typeof err === "object" && "code" in err
            ? (err as WalletError)
            : walletError(
                "connection_failed",
                err instanceof Error
                  ? err.message
                  : "Failed to connect wallet. Please try again.",
              );

        setWallet((prev) => ({ ...prev, error }));
      }
    },
    [saveSensitiveSessionToken, wallet.network],
  );

  // ── Disconnect ───────────────────────────────────────────────────────────

  const disconnect = useCallback(async () => {
    await clearWalletSession();
    await clearSensitiveSessionToken();

    const lastType = await getLastWalletType();

    setWallet({
      connected: false,
      publicKey: undefined,
      network: wallet.network,
      walletType: lastType ?? undefined,
      connectedAt: undefined,
      error: undefined,
      isRestoring: false,
    });
  }, [clearSensitiveSessionToken, wallet.network]);

  // ── Switch account (within same wallet provider) ─────────────────────────

  const switchAccount = useCallback(
    async (newPublicKey: string) => {
      if (!wallet.connected || !wallet.walletType) return;

      setWallet((prev) => ({ ...prev, error: undefined }));

      try {
        const now = Date.now();

        await saveWalletSession({
          publicKey: newPublicKey,
          network: wallet.network,
          walletType: wallet.walletType!,
          connectedAt: now,
          lastConfirmedAt: new Date(now).toISOString(),
        });

        setWallet((prev) => ({
          ...prev,
          publicKey: newPublicKey,
          connectedAt: now,
          error: undefined,
        }));
      } catch (err) {
        const error: WalletError = walletError(
          "connection_failed",
          err instanceof Error
            ? err.message
            : "Failed to switch account. Please try again.",
        );

        setWallet((prev) => ({ ...prev, error }));
      }
    },
    [wallet.connected, wallet.walletType, wallet.network],
  );

  // ── Switch network ───────────────────────────────────────────────────────

  const switchNetwork = useCallback((network: StellarNetwork) => {
    setWallet((prev) => ({ ...prev, network }));
  }, []);

  // ── Clear error ──────────────────────────────────────────────────────────

  const clearError = useCallback(() => {
    setWallet((prev) => ({ ...prev, error: undefined }));
  }, []);

  // ── Context value ────────────────────────────────────────────────────────

  const value = useMemo<WalletContextValue>(
    () => ({
      wallet,
      connect,
      disconnect,
      switchAccount,
      switchNetwork,
      clearError,
    }),
    [wallet, connect, disconnect, switchAccount, switchNetwork, clearError],
  );

  return (
    <WalletContext.Provider value={value}>{children}</WalletContext.Provider>
  );
};

// ── Hook ─────────────────────────────────────────────────────────────────────

export function useWalletContext(): WalletContextValue {
  const ctx = useContext(WalletContext);
  if (!ctx) {
    throw new Error("useWalletContext must be used within a WalletProvider");
  }
  return ctx;
}
