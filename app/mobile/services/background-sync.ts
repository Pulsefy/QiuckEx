import AsyncStorage from "@react-native-async-storage/async-storage";
import NetInfo from "@react-native-community/netinfo";
import { AppState, Platform } from "react-native";

import type { PaymentNotification } from "../components/notifications/types/notification";
import { fetchTransactions } from "./transactions";
import { getWalletSession } from "./wallet-session";
import type { TransactionItem } from "../types/transaction";

export type SyncFrequency = "battery-saver" | "balanced" | "frequent";
export type SyncReason = "app-launch" | "foreground" | "manual" | "background";

export interface BackgroundSyncSettings {
  enabled: boolean;
  badgeEnabled: boolean;
  wifiOnly: boolean;
  frequency: SyncFrequency;
}

export interface SyncSnapshot {
  currentAccountId: string | null;
  notifications: PaymentNotification[];
  recentActivity: TransactionItem[];
  lastSyncedAt: number | null;
  lastSuccessfulSyncAt: number | null;
  initialSyncCompleted: boolean;
}

export interface SyncExecutionResult {
  status: "updated" | "skipped" | "failed";
  reason: SyncReason;
  detail?:
    | "disabled"
    | "no-wallet"
    | "offline"
    | "wifi-required"
    | "unavailable"
    | "fetch-failed";
  error?: string;
  snapshot: SyncSnapshot;
}

const SYNC_SETTINGS_KEY = "quickex.background-sync.settings.v1";
const SYNC_SNAPSHOT_KEY = "quickex.background-sync.snapshot.v1";
const SYNC_TASK_NAME = "quickex.background-sync.task";
const MAX_NOTIFICATIONS = 50;
const MAX_ACTIVITY_ITEMS = 25;

export const SYNC_INTERVALS_MINUTES: Record<SyncFrequency, number> = {
  "battery-saver": 60,
  balanced: 30,
  frequent: 15,
};

export const DEFAULT_BACKGROUND_SYNC_SETTINGS: BackgroundSyncSettings = {
  enabled: true,
  badgeEnabled: true,
  wifiOnly: false,
  frequency: "balanced",
};

export const DEFAULT_SYNC_SNAPSHOT: SyncSnapshot = {
  currentAccountId: null,
  notifications: [],
  recentActivity: [],
  lastSyncedAt: null,
  lastSuccessfulSyncAt: null,
  initialSyncCompleted: false,
};

let backgroundTaskDefined = false;

function safeRequire(moduleName: string): any | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
    return require(moduleName);
  } catch {
    return null;
  }
}

function getBackgroundTaskModule() {
  return safeRequire("expo-background-task");
}

function getTaskManagerModule() {
  return safeRequire("expo-task-manager");
}

function getNotificationsModule() {
  return safeRequire("expo-notifications");
}

function notificationIdForTransaction(item: TransactionItem) {
  return item.txHash || item.pagingToken;
}

function toNotification(
  item: TransactionItem,
  accountId: string,
  read: boolean,
): PaymentNotification {
  const isIncoming = item.destination === accountId;
  const counterparty = isIncoming ? item.source : item.destination;

  return {
    id: notificationIdForTransaction(item),
    amount: item.amount,
    asset: item.asset,
    sender: counterparty,
    receivedAt: Date.parse(item.timestamp),
    read,
    direction: isIncoming ? "incoming" : "outgoing",
    memo: item.memo,
    txHash: item.txHash,
    pagingToken: item.pagingToken,
  };
}

function sortNotifications(items: PaymentNotification[]) {
  return [...items]
    .sort((left, right) => right.receivedAt - left.receivedAt)
    .slice(0, MAX_NOTIFICATIONS);
}

function sortActivity(items: TransactionItem[]) {
  return [...items]
    .sort(
      (left, right) =>
        Date.parse(right.timestamp) - Date.parse(left.timestamp),
    )
    .slice(0, MAX_ACTIVITY_ITEMS);
}

export function mergeSyncSnapshot(
  previous: SyncSnapshot,
  latestItems: TransactionItem[],
  accountId: string,
): SyncSnapshot {
  const notificationMap = new Map(
    previous.notifications.map((item) => [item.id, item]),
  );
  const activityMap = new Map(
    previous.recentActivity.map((item) => [item.pagingToken, item]),
  );
  const baselineRead = !previous.initialSyncCompleted;

  for (const item of latestItems) {
    activityMap.set(item.pagingToken, item);

    const notificationId = notificationIdForTransaction(item);
    if (!notificationMap.has(notificationId)) {
      notificationMap.set(
        notificationId,
        toNotification(item, accountId, baselineRead),
      );
    }
  }

  const now = Date.now();

  return {
    currentAccountId: accountId,
    notifications: sortNotifications(Array.from(notificationMap.values())),
    recentActivity: sortActivity(Array.from(activityMap.values())),
    lastSyncedAt: now,
    lastSuccessfulSyncAt: now,
    initialSyncCompleted: true,
  };
}

export async function getBackgroundSyncSettings(): Promise<BackgroundSyncSettings> {
  try {
    const raw = await AsyncStorage.getItem(SYNC_SETTINGS_KEY);
    if (!raw) return DEFAULT_BACKGROUND_SYNC_SETTINGS;

    const parsed = JSON.parse(raw) as Partial<BackgroundSyncSettings>;
    return {
      enabled:
        typeof parsed.enabled === "boolean"
          ? parsed.enabled
          : DEFAULT_BACKGROUND_SYNC_SETTINGS.enabled,
      badgeEnabled:
        typeof parsed.badgeEnabled === "boolean"
          ? parsed.badgeEnabled
          : DEFAULT_BACKGROUND_SYNC_SETTINGS.badgeEnabled,
      wifiOnly:
        typeof parsed.wifiOnly === "boolean"
          ? parsed.wifiOnly
          : DEFAULT_BACKGROUND_SYNC_SETTINGS.wifiOnly,
      frequency:
        parsed.frequency && parsed.frequency in SYNC_INTERVALS_MINUTES
          ? parsed.frequency
          : DEFAULT_BACKGROUND_SYNC_SETTINGS.frequency,
    };
  } catch {
    return DEFAULT_BACKGROUND_SYNC_SETTINGS;
  }
}

export async function saveBackgroundSyncSettings(
  settings: BackgroundSyncSettings,
): Promise<void> {
  await AsyncStorage.setItem(SYNC_SETTINGS_KEY, JSON.stringify(settings));
}

export async function getSyncSnapshot(): Promise<SyncSnapshot> {
  try {
    const raw = await AsyncStorage.getItem(SYNC_SNAPSHOT_KEY);
    if (!raw) return DEFAULT_SYNC_SNAPSHOT;

    const parsed = JSON.parse(raw) as Partial<SyncSnapshot>;
    return {
      currentAccountId: parsed.currentAccountId ?? null,
      notifications: Array.isArray(parsed.notifications)
        ? parsed.notifications
        : [],
      recentActivity: Array.isArray(parsed.recentActivity)
        ? parsed.recentActivity
        : [],
      lastSyncedAt:
        typeof parsed.lastSyncedAt === "number" ? parsed.lastSyncedAt : null,
      lastSuccessfulSyncAt:
        typeof parsed.lastSuccessfulSyncAt === "number"
          ? parsed.lastSuccessfulSyncAt
          : null,
      initialSyncCompleted: Boolean(parsed.initialSyncCompleted),
    };
  } catch {
    return DEFAULT_SYNC_SNAPSHOT;
  }
}

export async function saveSyncSnapshot(snapshot: SyncSnapshot): Promise<void> {
  await AsyncStorage.setItem(SYNC_SNAPSHOT_KEY, JSON.stringify(snapshot));
}

export async function updateStoredSyncSnapshot(
  updater: (snapshot: SyncSnapshot) => SyncSnapshot,
): Promise<SyncSnapshot> {
  const current = await getSyncSnapshot();
  const next = updater(current);
  await saveSyncSnapshot(next);
  return next;
}

export function getUnreadNotificationCount(snapshot: SyncSnapshot) {
  return snapshot.notifications.filter((item) => !item.read).length;
}

export async function syncAppBadgeCount(
  count: number,
  enabled: boolean,
  promptForPermissions = false,
): Promise<boolean> {
  const Notifications = getNotificationsModule();
  if (!Notifications?.setBadgeCountAsync) {
    return false;
  }

  if (promptForPermissions && Notifications.getPermissionsAsync) {
    try {
      const permissions = await Notifications.getPermissionsAsync();
      const granted =
        permissions?.granted || permissions?.ios?.allowsBadge === true;

      if (!granted && Notifications.requestPermissionsAsync) {
        await Notifications.requestPermissionsAsync({
          ios: { allowBadge: true, allowAlert: false, allowSound: false },
        });
      }
    } catch {
      // Ignore permission errors and still attempt to set the badge count.
    }
  }

  try {
    await Notifications.setBadgeCountAsync(enabled ? count : 0);
    return true;
  } catch {
    return false;
  }
}

export function getForegroundSyncIntervalMs(settings: BackgroundSyncSettings) {
  return SYNC_INTERVALS_MINUTES[settings.frequency] * 60 * 1000;
}

export function shouldSyncOnAppForeground(snapshot: SyncSnapshot) {
  if (!snapshot.lastSuccessfulSyncAt) return true;
  return Date.now() - snapshot.lastSuccessfulSyncAt > 2 * 60 * 1000;
}

export async function performBackgroundSync(
  reason: SyncReason,
): Promise<SyncExecutionResult> {
  const [settings, snapshot, walletSession] = await Promise.all([
    getBackgroundSyncSettings(),
    getSyncSnapshot(),
    getWalletSession(),
  ]);

  if (reason === "background" && !settings.enabled) {
    return { status: "skipped", reason, detail: "disabled", snapshot };
  }

  if (!walletSession?.publicKey) {
    return { status: "skipped", reason, detail: "no-wallet", snapshot };
  }

  const network = await NetInfo.fetch();
  if (!network.isConnected) {
    return { status: "skipped", reason, detail: "offline", snapshot };
  }

  if (settings.wifiOnly && network.type !== "wifi") {
    return { status: "skipped", reason, detail: "wifi-required", snapshot };
  }

  try {
    const response = await fetchTransactions(walletSession.publicKey, {
      limit: MAX_ACTIVITY_ITEMS,
    });

    const nextSnapshot = mergeSyncSnapshot(
      snapshot,
      response.items,
      walletSession.publicKey,
    );

    await saveSyncSnapshot(nextSnapshot);
    await syncAppBadgeCount(
      getUnreadNotificationCount(nextSnapshot),
      settings.badgeEnabled,
      reason !== "background" && AppState.currentState === "active",
    );

    return {
      status: "updated",
      reason,
      snapshot: nextSnapshot,
    };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Background sync failed.";

    return {
      status: "failed",
      reason,
      detail: "fetch-failed",
      error: message,
      snapshot,
    };
  }
}

function ensureBackgroundTaskDefined() {
  if (backgroundTaskDefined) return;

  const BackgroundTask = getBackgroundTaskModule();
  const TaskManager = getTaskManagerModule();

  if (!BackgroundTask || !TaskManager?.defineTask) {
    return;
  }

  TaskManager.defineTask(SYNC_TASK_NAME, async () => {
    const result = await performBackgroundSync("background");

    if (result.status === "failed") {
      return BackgroundTask.BackgroundTaskResult?.Failed ?? "Failed";
    }

    return BackgroundTask.BackgroundTaskResult?.Success ?? "Success";
  });

  backgroundTaskDefined = true;
}

export async function configureBackgroundSyncTask(
  settings: BackgroundSyncSettings,
): Promise<{ available: boolean; registered: boolean }> {
  if (Platform.OS === "web") {
    return { available: false, registered: false };
  }

  const BackgroundTask = getBackgroundTaskModule();
  const TaskManager = getTaskManagerModule();

  if (
    !BackgroundTask?.registerTaskAsync ||
    !BackgroundTask?.unregisterTaskAsync ||
    !TaskManager?.isTaskRegisteredAsync
  ) {
    return { available: false, registered: false };
  }

  ensureBackgroundTaskDefined();

  const registered = await TaskManager.isTaskRegisteredAsync(SYNC_TASK_NAME);
  if (registered) {
    await BackgroundTask.unregisterTaskAsync(SYNC_TASK_NAME).catch(() => {});
  }

  if (!settings.enabled) {
    return { available: true, registered: false };
  }

  await BackgroundTask.registerTaskAsync(SYNC_TASK_NAME, {
    minimumInterval: getForegroundSyncIntervalMs(settings) / 1000,
  }).catch(() => {});

  const nextRegistered = await TaskManager.isTaskRegisteredAsync(
    SYNC_TASK_NAME,
  ).catch(() => false);

  return { available: true, registered: nextRegistered };
}
