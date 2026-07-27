import NetInfo from "@react-native-community/netinfo";

import {
  markAllInAppNotificationsRead,
  markInAppNotificationRead,
} from "./in-app-notifications";
import {
  enqueueAction,
  processOfflineQueue,
  registerActionHandler,
} from "./offline-queue";

export const MARK_READ_ACTION = "notification.mark-read";
export const MARK_ALL_READ_ACTION = "notification.mark-all-read";

export type MarkReadSyncResult =
  | { status: "synced" }
  | { status: "queued"; reason: "offline" | "request-failed" }
  | { status: "skipped"; reason: "missing-id" | "missing-public-key" };

let handlersRegistered = false;

/**
 * Registers offline-queue handlers for notification read mutations.
 * Safe to call multiple times.
 */
export function registerNotificationReadHandlers(): void {
  if (handlersRegistered) return;
  handlersRegistered = true;

  registerActionHandler(MARK_READ_ACTION, async (payload: { id?: string }) => {
    if (!payload?.id) {
      throw new Error("Missing notification id for mark-read action");
    }
    await markInAppNotificationRead(payload.id);
  });

  registerActionHandler(
    MARK_ALL_READ_ACTION,
    async (payload: { publicKey?: string }) => {
      if (!payload?.publicKey) {
        throw new Error("Missing publicKey for mark-all-read action");
      }
      await markAllInAppNotificationsRead(payload.publicKey);
    },
  );
}

async function isOnline(): Promise<boolean> {
  try {
    const state = await NetInfo.fetch();
    return Boolean(state.isConnected && state.isInternetReachable !== false);
  } catch {
    return false;
  }
}

/**
 * Sync a single notification mark-read to the backend.
 * Queues the mutation when offline or when the request fails.
 */
export async function syncMarkNotificationRead(
  id: string,
): Promise<MarkReadSyncResult> {
  if (!id) {
    return { status: "skipped", reason: "missing-id" };
  }

  registerNotificationReadHandlers();

  const online = await isOnline();
  if (!online) {
    await enqueueAction(MARK_READ_ACTION, { id });
    return { status: "queued", reason: "offline" };
  }

  try {
    await markInAppNotificationRead(id);
    return { status: "synced" };
  } catch {
    await enqueueAction(MARK_READ_ACTION, { id });
    return { status: "queued", reason: "request-failed" };
  }
}

/**
 * Sync mark-all-read to the backend.
 * Queues the mutation when offline or when the request fails.
 */
export async function syncMarkAllNotificationsRead(
  publicKey: string | null | undefined,
): Promise<MarkReadSyncResult> {
  if (!publicKey) {
    return { status: "skipped", reason: "missing-public-key" };
  }

  registerNotificationReadHandlers();

  const online = await isOnline();
  if (!online) {
    await enqueueAction(MARK_ALL_READ_ACTION, { publicKey });
    return { status: "queued", reason: "offline" };
  }

  try {
    await markAllInAppNotificationsRead(publicKey);
    return { status: "synced" };
  } catch {
    await enqueueAction(MARK_ALL_READ_ACTION, { publicKey });
    return { status: "queued", reason: "request-failed" };
  }
}

/**
 * Flushes pending notification read mutations.
 * Call on app resume / reconnect so delayed sync does not leave state stuck.
 */
export async function flushNotificationReadQueue(): Promise<void> {
  registerNotificationReadHandlers();
  await processOfflineQueue();
}
