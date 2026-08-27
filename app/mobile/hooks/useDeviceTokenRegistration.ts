import NetInfo from "@react-native-community/netinfo";
import { useEffect, useRef } from "react";
import { AppState, type AppStateStatus, Platform } from "react-native";

import {
  deregisterDeviceToken,
  flushDeviceTokenQueue,
  getNotificationsModule,
  getPermissionStatus,
  handlePermissionRevoked,
  reconcileInstallation,
  registerDeviceToken,
} from "../services/device-token-registration";
import type { RegisterResult } from "../services/device-token-registration";
import { getWalletSession } from "../services/wallet-session";

/**
 * Mounts the device-token registration lifecycle at the app root.
 *
 * Responsibilities (in priority order):
 *
 *   1. On mount: detect reinstall/restore via installation-id mismatch and
 *      supersede the previous registration. The previous token is dropped
 *      on the backend; the new one is registered on connect.
 *   2. On AppState change to "active": flush any queued retries and
 *      reconcile (handles granted-after-denied, OS-level token refresh,
 *      and offline-to-online transitions).
 *   3. On NetInfo reconnect: flush queued retries.
 *   4. On Expo push-token refresh: re-register against the current wallet.
 *   5. On permission revoke: clear local state and queue a deregister so the
 *      backend stops pushing to this device.
 *
 * The hook intentionally does not trigger an explicit "register on first
 * grant" — that happens inside the wallet connect path, which is the
 * authoritative moment a user becomes eligible for notifications.
 */
export function useDeviceTokenRegistration(): void {
  const lastPermissionRef = useRef<string | null>(null);
  const hasMountedRef = useRef(false);

  useEffect(() => {
    let cancelled = false;
    const Notifications = getNotificationsModule();

    // 1) Reinstall/restore detection. We do this once on mount, before
    //    anything else, so a stale token from a previous install can be
    //    cleaned up before the user even sees the home screen.
    void (async () => {
      try {
        const session = await getWalletSession();
        if (cancelled) return;
        await reconcileInstallation({ publicKey: session?.publicKey });
      } catch (error) {
        console.warn("[device-token] reconcile on mount failed:", error);
      }
    })();

    // 2) Cache the current permission so we can detect transitions on
    //    resume (granted → denied after a user toggles in Settings, or
    //    denied → granted after they re-enable).
    void getPermissionStatus().then((status) => {
      lastPermissionRef.current = status;
    });

    // 3) Listen for OS-driven push-token refresh. Expo emits this event
    //    when the underlying APNs / FCM token rotates, which is the most
    //    common cause of "notifications stopped arriving" with no visible
    //    cause.
    let pushTokenSubscription: { remove?: () => void } | null = null;
    if (Notifications?.addPushTokenListener) {
      pushTokenSubscription = Notifications.addPushTokenListener(async () => {
        try {
          const session = await getWalletSession();
          if (!session?.publicKey) return;
          const result: RegisterResult = await registerDeviceToken({
            publicKey: session.publicKey,
            force: true,
          });
          if (cancelled) return;
          if (result.status === "denied") {
            await handlePermissionRevoked();
          }
        } catch (error) {
          console.warn("[device-token] push-token refresh handler failed:", error);
        }
      });
    }

    hasMountedRef.current = true;

    return () => {
      cancelled = true;
      if (pushTokenSubscription && typeof pushTokenSubscription.remove === "function") {
        pushTokenSubscription.remove();
      }
    };
  }, []);

  // 4) AppState / permission reconcile on resume.
  useEffect(() => {
    function handleAppStateChange(next: AppStateStatus) {
      if (next !== "active") return;
      void onAppForeground({
        lastPermissionRef,
        onRevoked: handlePermissionRevoked,
      });
    }

    const sub = AppState.addEventListener("change", handleAppStateChange);
    return () => sub.remove();
  }, []);

  // 5) Reconnect → flush queued retries.
  useEffect(() => {
    if (Platform.OS === "web") return;
    const unsubscribe = NetInfo.addEventListener((state) => {
      if (state.isConnected && state.isInternetReachable !== false) {
        flushDeviceTokenQueue().catch((error) => {
          console.warn("[device-token] queue flush on reconnect failed:", error);
        });
      }
    });
    return () => unsubscribe();
  }, []);
}

async function onAppForeground(args: {
  lastPermissionRef: React.MutableRefObject<string | null>;
  onRevoked: () => Promise<void>;
}): Promise<void> {
  try {
    // Drain any pending retries first so an offline-then-online transition
    // doesn't leave the backend out of sync.
    await flushDeviceTokenQueue();
  } catch (error) {
    console.warn("[device-token] foreground queue flush failed:", error);
  }

  const currentPermission = await getPermissionStatus();
  const previousPermission = args.lastPermissionRef.current;

  // Permission transitions:
  //   granted → denied : drop local record; queue a backend deregister.
  //   denied  → granted: clear any negative cache; the next connect (or
  //                     the explicit registration on next foreground)
  //                     will pick this up.
  if (previousPermission === "granted" && currentPermission !== "granted") {
    await args.onRevoked();
    const session = await getWalletSession();
    if (session?.publicKey) {
      await deregisterDeviceToken({ publicKey: session.publicKey });
    }
  }

  args.lastPermissionRef.current = currentPermission;

  // If we already have a wallet session, refresh the token in case the
  // OS rotated it while we were backgrounded. The registration function
  // is a no-op when nothing changed.
  const session = await getWalletSession();
  if (session?.publicKey && currentPermission === "granted") {
    await registerDeviceToken({ publicKey: session.publicKey });
  }
}
