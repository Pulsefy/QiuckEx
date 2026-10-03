"use client";

import { useState, useCallback, useEffect, useMemo } from "react";

export type WalletType = "freighter" | "lobstr" | "xbull" | "albedo" | "demo";

export type StellarNetwork = "testnet" | "mainnet";

export interface WalletError {
  code:
    | "wallet_locked"
    | "wrong_network"
    | "signature_rejected"
    | "connection_failed"
    | "wallet_not_found"
    | "session_expired";
  message: string;
  recoverable: boolean;
}

export interface WalletState {
  connected: boolean;
  publicKey: string | null;
  network: StellarNetwork;
  walletType: WalletType | null;
  error: WalletError | null;
}

const STORAGE_KEY = "quickex.wallet.session";

interface StoredWalletSession {
  publicKey: string;
  network: StellarNetwork;
  walletType: WalletType;
  connectedAt: number;
}

function getStoredSession(): StoredWalletSession | null {
  if (typeof window === "undefined") return null;
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return null;
    const parsed = JSON.parse(stored) as StoredWalletSession;
    return parsed;
  } catch {
    return null;
  }
}

function saveSession(session: StoredWalletSession): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
}

function clearSession(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(STORAGE_KEY);
}

function isFreighterAvailable(): boolean {
  return typeof window !== "undefined" && "freighter" in window;
}

function isAlbedoAvailable(): boolean {
  return typeof window !== "undefined" && "albedo" in window;
}

async function requestFreighterAccess(): Promise<string> {
  if (!isFreighterAvailable()) {
    throw new Error("Freighter extension not detected");
  }
  // @ts-expect-error - freighter is injected by the browser extension
  const { address } = await window.freighter.requestAccess();
  return address;
}

async function getFreighterPublicKey(): Promise<string> {
  if (!isFreighterAvailable()) {
    throw new Error("Freighter extension not detected");
  }
  // @ts-expect-error - freighter is injected by the browser extension
  const { address } = await window.freighter.getPublicKey();
  return address;
}

async function signWithFreighter(
  xdr: string,
  network: StellarNetwork,
): Promise<string> {
  if (!isFreighterAvailable()) {
    throw new Error("Freighter extension not detected");
  }
  const networkPassphrase =
    network === "mainnet"
      ? "Public Global Stellar Network ; September 2015"
      : "Test SDF Network ; September 2015";
  // @ts-expect-error - freighter is injected by the browser extension
  const { signedTxXdr } = await window.freighter.signTransaction(xdr, {
    network: networkPassphrase,
  });
  return signedTxXdr;
}

async function getFreighterNetwork(): Promise<StellarNetwork> {
  if (!isFreighterAvailable()) {
    throw new Error("Freighter extension not detected");
  }
  // @ts-expect-error - freighter is injected by the browser extension
  const { network } = await window.freighter.getNetwork();
  return network === "mainnet" ? "mainnet" : "testnet";
}

async function signWithAlbedo(
  xdr: string,
  network: StellarNetwork,
): Promise<string> {
  if (!isAlbedoAvailable()) {
    throw new Error("Albedo not available");
  }
  // @ts-expect-error - albedo is injected by the Albedo extension
  const signedXdr = await window.albedo.signTransaction(xdr, {
    network: network === "mainnet" ? "mainnet" : "testnet",
  });
  return signedXdr;
}

async function getAlbedoPublicKey(): Promise<string> {
  if (!isAlbedoAvailable()) {
    throw new Error("Albedo not available");
  }
  // @ts-expect-error - albedo is injected by the Albedo extension
  return window.albedo.getPublicKey();
}

export function useWallet() {
  const [state, setState] = useState<WalletState>({
    connected: false,
    publicKey: null,
    network: "testnet",
    walletType: null,
    error: null,
  });

  const [isRestoring, setIsRestoring] = useState(true);

  const setError = useCallback((error: WalletError | null) => {
    setState((prev) => ({ ...prev, error }));
  }, []);

  const clearError = useCallback(() => {
    setState((prev) => ({ ...prev, error: null }));
  }, []);

  const restoreSession = useCallback(async () => {
    try {
      const stored = getStoredSession();
      if (stored) {
        let currentPublicKey: string | null = null;

        if (stored.walletType === "freighter" && isFreighterAvailable()) {
          try {
            currentPublicKey = await getFreighterPublicKey();
          } catch {
            // Wallet not accessible
          }
        } else if (stored.walletType === "albedo" && isAlbedoAvailable()) {
          try {
            currentPublicKey = await getAlbedoPublicKey();
          } catch {
            // Wallet not accessible
          }
        }

        if (currentPublicKey && currentPublicKey === stored.publicKey) {
          setState({
            connected: true,
            publicKey: currentPublicKey,
            network: stored.network,
            walletType: stored.walletType,
            error: null,
          });
        } else {
          clearSession();
        }
      }
    } catch (err) {
      console.warn("Failed to restore wallet session:", err);
    } finally {
      setIsRestoring(false);
    }
  }, []);

  useEffect(() => {
    restoreSession();
  }, [restoreSession]);

  const connect = useCallback(
    async (walletType: WalletType, network?: StellarNetwork) => {
      setError(null);
      setState((prev) => ({ ...prev, error: null }));

      try {
        const targetNetwork = network ?? state.network ?? "testnet";
        let publicKey: string;

        if (walletType === "freighter") {
          if (!isFreighterAvailable()) {
            throw {
              code: "wallet_not_found",
              message:
                "Freighter extension not found. Please install Freighter from https://freighter.app",
              recoverable: true,
            } as WalletError;
          }
          publicKey = await requestFreighterAccess();
          const walletNetwork = await getFreighterNetwork();
          if (walletNetwork !== targetNetwork) {
            throw {
              code: "wrong_network",
              message: `Freighter is on ${walletNetwork}. Please switch to ${targetNetwork} in Freighter and try again.`,
              recoverable: true,
            } as WalletError;
          }
        } else if (walletType === "albedo") {
          if (!isAlbedoAvailable()) {
            throw {
              code: "wallet_not_found",
              message:
                "Albedo not available. Please ensure Albedo is running.",
              recoverable: true,
            } as WalletError;
          }
          publicKey = await getAlbedoPublicKey();
        } else if (walletType === "demo") {
          publicKey =
            "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP";
        } else {
          throw {
            code: "wallet_not_found",
            message: `${walletType} wallet connector not yet implemented in web. Use Freighter or Albedo.`,
            recoverable: true,
          } as WalletError;
        }

        const now = Date.now();
        saveSession({
          publicKey,
          network: targetNetwork,
          walletType,
          connectedAt: now,
        });

        setState({
          connected: true,
          publicKey,
          network: targetNetwork,
          walletType,
          error: null,
        });
      } catch (err) {
        const error: WalletError =
          err && typeof err === "object" && "code" in err
            ? (err as WalletError)
            : {
                code: "connection_failed",
                message:
                  err instanceof Error
                    ? err.message
                    : "Failed to connect wallet. Please try again.",
                recoverable: true,
              };
        setState((prev) => ({ ...prev, error }));
        throw err;
      }
    },
    [state.network, setError],
  );

const disconnect = useCallback(async () => {
    clearSession();
    setState((prev) => ({
      ...prev,
      connected: false,
      publicKey: null,
      walletType: null,
      error: null,
    }));
  }, []);

  const switchNetwork = useCallback((network: StellarNetwork) => {
    setState((prev) => ({ ...prev, network }));
  }, []);

  const signTransaction = useCallback(
    async (xdr: string): Promise<string> => {
      if (!state.connected || !state.walletType || !state.publicKey) {
        throw new Error("Wallet not connected");
      }

      if (state.walletType === "freighter") {
        return signWithFreighter(xdr, state.network);
      } else if (state.walletType === "albedo") {
        return signWithAlbedo(xdr, state.network);
      } else if (state.walletType === "demo") {
        // For demo, return a mock signed XDR (in real app, this would be a testnet signer)
        return "AAAAA" + Math.random().toString(36).substring(7).toUpperCase() + "xdrSignedPayload314159265358979323846264";
      }

      throw new Error(`Signing not supported for ${state.walletType}`);
    },
    [state.connected, state.walletType, state.network, state.publicKey],
  );

  const availableWallets = useMemo(() => {
    const wallets: Array<{ type: WalletType; label: string; available: boolean; description: string }> = [
      {
        type: "freighter",
        label: "Freighter",
        available: isFreighterAvailable(),
        description: "Browser extension by Stellar Development Foundation",
      },
      {
        type: "albedo",
        label: "Albedo",
        available: isAlbedoAvailable(),
        description: "Session-based signing — no extension needed",
      },
      {
        type: "demo",
        label: "Demo Wallet",
        available: true,
        description: "Testnet demo account for quick exploration",
      },
    ];
    return wallets;
  }, []);

  return {
    wallet: state,
    isRestoring,
    connect,
    disconnect,
    switchNetwork,
    signTransaction,
    clearError,
    availableWallets,
  };
}