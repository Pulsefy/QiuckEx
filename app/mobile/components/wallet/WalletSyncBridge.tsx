import { useEffect, useRef } from "react";

import { useNotifications } from "../components/notifications/NotificationContext";
import { useWalletContext } from "../hooks/useWalletContext";

/**
 * WalletSyncBridge — watches wallet state and triggers a notification
 * re-sync whenever the connected public key changes.
 *
 * Place this component once inside the provider tree (after both
 * WalletProvider and NotificationProvider are mounted).
 */
export function WalletSyncBridge() {
  const { wallet } = useWalletContext();
  const { syncNow } = useNotifications();
  const prevPublicKeyRef = useRef<string | undefined>(undefined);

  useEffect(() => {
    const currentKey = wallet.connected ? wallet.publicKey : undefined;

    // Only re-sync when the public key actually changes
    if (currentKey !== prevPublicKeyRef.current) {
      prevPublicKeyRef.current = currentKey;
      void syncNow();
    }
  }, [wallet.connected, wallet.publicKey, syncNow]);

  return null;
}
