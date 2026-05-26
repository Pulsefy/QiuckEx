import { AppState, type AppStateStatus } from "react-native";
import { useCallback, useEffect, useState } from "react";
import { useWalletContext } from "./useWalletContext";
import type { StellarNetwork, WalletType } from "../types/wallet";

/**
 * Configuration for network guard behavior
 */
export interface NetworkGuardConfig {
  expectedNetwork: StellarNetwork;
  listenForNetworkEvents: boolean;
  listenForFocusEvents: boolean;
}

/**
 * Result of network mismatch detection
 */
export interface NetworkGuardState {
  isConnected: boolean;
  currentNetwork: StellarNetwork;
  expectedNetwork: StellarNetwork;
  isMismatched: boolean;
  walletType: WalletType | undefined;
  isRestoring: boolean;
  lastVerifiedAt: number | null;
  verifyNetwork: () => void;
}

/**
 * Custom hook that detects network mismatches between wallet and app expectations.
 *
 * Features:
 * - Cold start detection (on mount)
 * - Network switch event detection
 * - Focus/resume listener for multi-app scenarios
 * - Configurable expected network
 *
 * @param expectedNetwork - The network the app expects (typically "testnet")
 * @returns Current network guard state
 */
export function useNetworkGuard(
  expectedNetwork: StellarNetwork = "testnet",
): NetworkGuardState {
  const { wallet } = useWalletContext();
  const [isRestoring, setIsRestoring] = useState(true);
  const [hasChecked, setHasChecked] = useState(false);
  const [lastVerifiedAt, setLastVerifiedAt] = useState<number | null>(null);

  const verifyNetwork = useCallback(() => {
    setLastVerifiedAt(Date.now());
  }, []);

  // Calculate mismatch status
  const isMismatched =
    wallet.connected && wallet.network !== expectedNetwork;

  // Mark as done restoring on first render with wallet data
  useEffect(() => {
    if (!wallet.isRestoring && !hasChecked) {
      verifyNetwork();
      setIsRestoring(false);
      setHasChecked(true);
    }
  }, [wallet.isRestoring, hasChecked, verifyNetwork]);

  useEffect(() => {
    verifyNetwork();
  }, [wallet.connected, wallet.network, wallet.walletType, verifyNetwork]);

  // Listen for network switch events from wallet extensions.
  useEffect(() => {
    if (typeof window === "undefined") return;

    const handleNetworkChange = () => {
      verifyNetwork();
    };

    window.addEventListener("stellar:networkchange", handleNetworkChange);
    window.addEventListener("stellar:networkChanged", handleNetworkChange);
    window.addEventListener("freighter:networkChanged", handleNetworkChange);

    return () => {
      window.removeEventListener("stellar:networkchange", handleNetworkChange);
      window.removeEventListener("stellar:networkChanged", handleNetworkChange);
      window.removeEventListener("freighter:networkChanged", handleNetworkChange);
    };
  }, [verifyNetwork]);

  // Re-check when web/desktop regains focus or visibility.
  useEffect(() => {
    if (typeof window === "undefined") return;

    const handleFocus = () => verifyNetwork();
    const handleVisibilityChange = () => {
      if (typeof document === "undefined" || document.visibilityState === "visible") {
        verifyNetwork();
      }
    };

    window.addEventListener("focus", handleFocus);
    document?.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      window.removeEventListener("focus", handleFocus);
      document?.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [verifyNetwork]);

  // Re-check when native app resumes from the background.
  useEffect(() => {
    const handleAppStateChange = (nextState: AppStateStatus) => {
      if (nextState === "active") {
        verifyNetwork();
      }
    };

    const subscription = AppState.addEventListener("change", handleAppStateChange);
    return () => subscription.remove();
  }, [verifyNetwork]);

  return {
    isConnected: wallet.connected,
    currentNetwork: wallet.network,
    expectedNetwork,
    isMismatched,
    walletType: wallet.walletType,
    isRestoring,
    lastVerifiedAt,
    verifyNetwork,
  };
}
