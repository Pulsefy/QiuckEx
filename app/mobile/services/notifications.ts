import AsyncStorage from "@react-native-async-storage/async-storage";
import NetInfo from "@react-native-community/netinfo";

import type { Notification } from "../types/notification";
import {
  countUnreadInAppNotifications,
  fetchInAppNotifications,
  type InAppNotificationDto,
} from "./in-app-notifications";
import {
  syncMarkAllNotificationsRead,
  syncMarkNotificationRead,
} from "./notification-read-sync";
import { getWalletSession } from "./wallet-session";

const NOTIFICATIONS_KEY = "app_notifications";

// Seed data used only when the device has never synced and is offline.
const MOCK_NOTIFICATIONS: Notification[] = [
  {
    id: "1",
    title: "Payment Received",
    message: "You received $50.00 from John Doe",
    type: "payment",
    read: false,
    createdAt: Date.now() - 3600000,
    data: { amount: "50.00", sender: "John Doe" },
  },
  {
    id: "2",
    title: "Escrow Released",
    message: "Escrow #1234 has been released successfully",
    type: "escrow",
    read: false,
    createdAt: Date.now() - 7200000,
    data: { escrowId: "1234" },
  },
  {
    id: "3",
    title: "Welcome to QiuckEx!",
    message: "Thanks for joining QiuckEx. Start your crypto journey today!",
    type: "system",
    read: true,
    createdAt: Date.now() - 86400000,
  },
];

function mapEventType(
  eventType: string,
): Notification["type"] {
  const normalized = eventType.toLowerCase();
  if (normalized.includes("escrow")) return "escrow";
  if (
    normalized.includes("payment") ||
    normalized.includes("recurring") ||
    normalized.includes("reconciliation")
  ) {
    return "payment";
  }
  return "system";
}

export function mapInAppNotification(
  item: InAppNotificationDto,
): Notification {
  const metadata = (item.metadata ?? {}) as Record<string, unknown>;
  return {
    id: item.id,
    title: item.title,
    message: item.body,
    type: mapEventType(item.eventType),
    read: Boolean(item.read),
    createdAt: Date.parse(item.createdAt) || Date.now(),
    data: {
      transactionId:
        typeof metadata.transactionId === "string"
          ? metadata.transactionId
          : item.eventId,
      amount:
        typeof metadata.amount === "string" ? metadata.amount : undefined,
      sender:
        typeof metadata.sender === "string" ? metadata.sender : undefined,
      recipient:
        typeof metadata.recipient === "string"
          ? metadata.recipient
          : undefined,
      escrowId:
        typeof metadata.escrowId === "string"
          ? metadata.escrowId
          : typeof metadata.commitment === "string"
            ? metadata.commitment
            : undefined,
    },
  };
}

/**
 * Prefer remote read flags when the same notification exists locally so a
 * delayed offline mark-read cannot resurrect an unread badge after sync.
 */
export function mergeNotificationReadState(
  local: Notification[],
  remote: Notification[],
): Notification[] {
  const localById = new Map(local.map((item) => [item.id, item]));
  const remoteIds = new Set(remote.map((item) => item.id));

  const mergedRemote = remote.map((remoteItem) => {
    const localItem = localById.get(remoteItem.id);
    if (!localItem) return remoteItem;
    // Once either side says read, keep it read to avoid corruption on delayed sync.
    return {
      ...remoteItem,
      read: remoteItem.read || localItem.read,
    };
  });

  // Keep optimistic local-only items that have not landed on the backend yet.
  const pendingLocal = local.filter((item) => !remoteIds.has(item.id));
  return [...mergedRemote, ...pendingLocal].sort(
    (left, right) => right.createdAt - left.createdAt,
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

export async function getCachedNotifications(): Promise<Notification[]> {
  try {
    const stored = await AsyncStorage.getItem(NOTIFICATIONS_KEY);
    if (stored) {
      return JSON.parse(stored) as Notification[];
    }
    return [];
  } catch (error) {
    console.error("Error loading notifications:", error);
    return [];
  }
}

export async function saveNotifications(
  notifications: Notification[],
): Promise<void> {
  try {
    await AsyncStorage.setItem(
      NOTIFICATIONS_KEY,
      JSON.stringify(notifications),
    );
  } catch (error) {
    console.error("Error saving notifications:", error);
  }
}

/**
 * Loads notifications from cache, refreshing from the backend when online.
 */
export async function getNotifications(): Promise<Notification[]> {
  const cached = await getCachedNotifications();

  if (!(await isOnline())) {
    if (cached.length > 0) return cached;
    await saveNotifications(MOCK_NOTIFICATIONS);
    return MOCK_NOTIFICATIONS;
  }

  try {
    const session = await getWalletSession();
    if (!session?.publicKey) {
      if (cached.length > 0) return cached;
      await saveNotifications(MOCK_NOTIFICATIONS);
      return MOCK_NOTIFICATIONS;
    }

    const remote = await fetchInAppNotifications(session.publicKey);
    const mapped = remote.map(mapInAppNotification);
    const merged = mergeNotificationReadState(cached, mapped);
    await saveNotifications(merged);
    return merged;
  } catch (error) {
    console.error("Error refreshing notifications from backend:", error);
    if (cached.length > 0) return cached;
    await saveNotifications(MOCK_NOTIFICATIONS);
    return MOCK_NOTIFICATIONS;
  }
}

async function loadLocalNotifications(): Promise<Notification[]> {
  const cached = await getCachedNotifications();
  if (cached.length > 0) return cached;
  return getNotifications();
}

/**
 * Optimistic local mark-read + backend / offline-queue sync.
 */
export async function markAsRead(notificationId: string): Promise<void> {
  const notifications = await loadLocalNotifications();
  const updated = notifications.map((n) =>
    n.id === notificationId ? { ...n, read: true } : n,
  );
  await saveNotifications(updated);
  await syncMarkNotificationRead(notificationId);
}

/**
 * Optimistic local mark-all-read + backend / offline-queue sync.
 */
export async function markAllAsRead(): Promise<void> {
  const notifications = await loadLocalNotifications();
  const updated = notifications.map((n) => ({ ...n, read: true }));
  await saveNotifications(updated);

  const session = await getWalletSession();
  await syncMarkAllNotificationsRead(session?.publicKey);
}

export async function deleteNotification(
  notificationId: string,
): Promise<void> {
  const notifications = await getCachedNotifications();
  const updated = notifications.filter((n) => n.id !== notificationId);
  await saveNotifications(updated);
}

export async function getUnreadCount(): Promise<number> {
  const notifications = await getCachedNotifications();
  if (notifications.length > 0) {
    return countUnreadInAppNotifications(notifications);
  }

  const fresh = await getNotifications();
  return countUnreadInAppNotifications(fresh);
}
