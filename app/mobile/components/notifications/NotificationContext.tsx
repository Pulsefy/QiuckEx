import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { AppState } from "react-native";
import { useSession } from "../../contexts/SessionContext";

import { PaymentNotification } from "./types/notification";
import {
  DEFAULT_BACKGROUND_SYNC_SETTINGS,
  DEFAULT_SYNC_SNAPSHOT,
  type BackgroundSyncSettings,
  configureBackgroundSyncTask,
  getBackgroundSyncSettings,
  getForegroundSyncIntervalMs,
  getSyncSnapshot,
  getUnreadNotificationCount,
  performBackgroundSync,
  saveBackgroundSyncSettings,
  shouldSyncOnAppForeground,
  syncAppBadgeCount,
  updateStoredSyncSnapshot,
} from "../../services/background-sync";
import {
  flushNotificationReadQueue,
  registerNotificationReadHandlers,
  syncMarkAllNotificationsRead,
} from "../../services/notification-read-sync";
import { getUnreadCount, markAllAsRead as markInboxAllAsRead } from "../../services/notifications";
import type { TransactionItem } from "../../types/transaction";

type NotificationContextShape = {
  notifications: PaymentNotification[];
  recentActivity: TransactionItem[];
  unreadCount: number;
  currentAccountId: string | null;
  backgroundSyncSettings: BackgroundSyncSettings;
  backgroundTaskAvailable: boolean;
  isHydrated: boolean;
  isSyncing: boolean;
  lastSyncedAt: number | null;
  addNotification: (n: PaymentNotification) => void;
  markRead: (id: string) => Promise<void>;
  markAllRead: () => Promise<void>;
  syncNow: () => Promise<void>;
  setBackgroundSyncSettings: (
    updater:
      | BackgroundSyncSettings
      | ((current: BackgroundSyncSettings) => BackgroundSyncSettings),
  ) => Promise<void>;
  soundEnabled: boolean;
  setSoundEnabled: (v: boolean) => void;
};

const STORAGE_KEY = "qex_sound_enabled_v1";

const NotificationContext = createContext<NotificationContextShape | undefined>(
  undefined,
);

export const NotificationProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [notifications, setNotifications] = useState<PaymentNotification[]>(
    DEFAULT_SYNC_SNAPSHOT.notifications,
  );
  const [recentActivity, setRecentActivity] = useState<TransactionItem[]>(
    DEFAULT_SYNC_SNAPSHOT.recentActivity,
  );
  const [currentAccountId, setCurrentAccountId] = useState<string | null>(
    DEFAULT_SYNC_SNAPSHOT.currentAccountId,
  );
  const [lastSyncedAt, setLastSyncedAt] = useState<number | null>(
    DEFAULT_SYNC_SNAPSHOT.lastSyncedAt,
  );
  const [backgroundSyncSettings, setBackgroundSyncSettingsState] =
    useState<BackgroundSyncSettings>(DEFAULT_BACKGROUND_SYNC_SETTINGS);
  const [backgroundTaskAvailable, setBackgroundTaskAvailable] =
    useState<boolean>(false);
  const [isHydrated, setIsHydrated] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [soundEnabled, setSoundEnabledState] = useState<boolean>(true);
  const { data: sessionData } = useSession();
  const [inboxUnreadCount, setInboxUnreadCount] = useState(sessionData?.unreadCount ?? 0);

  useEffect(() => {
    if (sessionData?.unreadCount !== undefined) {
      setInboxUnreadCount(sessionData.unreadCount);
    }
  }, [sessionData?.unreadCount]);

  useEffect(() => {
    registerNotificationReadHandlers();

    Promise.all([
      AsyncStorage.getItem(STORAGE_KEY),
      getBackgroundSyncSettings(),
      getSyncSnapshot(),
    ])
      .then(([soundValue, settings, snapshot]) => {
        setSoundEnabledState(soundValue !== "0");
        setBackgroundSyncSettingsState(settings);
        setNotifications(snapshot.notifications);
        setRecentActivity(snapshot.recentActivity);
        setCurrentAccountId(snapshot.currentAccountId);
        setLastSyncedAt(snapshot.lastSuccessfulSyncAt);
        setIsHydrated(true);
      })
      .catch(() => {
        setIsHydrated(true);
      });
  }, []);

  const setSoundEnabled = useCallback((v: boolean) => {
    setSoundEnabledState(v);
    AsyncStorage.setItem(STORAGE_KEY, v ? "1" : "0").catch(() => {});
  }, []);

  const refreshInboxUnreadCount = useCallback(async () => {
    try {
      const count = await getUnreadCount();
      setInboxUnreadCount(count);
      return count;
    } catch {
      return 0;
    }
  }, []);

  const persistAndBadge = useCallback(
    async (next: PaymentNotification[]) => {
      const snapshot = await updateStoredSyncSnapshot((current) => ({
        ...current,
        notifications: next,
      }));

      const paymentUnread = getUnreadNotificationCount(snapshot);
      const inboxUnread = await refreshInboxUnreadCount();
      await syncAppBadgeCount(
        Math.max(paymentUnread, inboxUnread),
        backgroundSyncSettings.badgeEnabled,
      );
    },
    [backgroundSyncSettings.badgeEnabled, refreshInboxUnreadCount],
  );

  const addNotification = useCallback((n: PaymentNotification) => {
    setNotifications((prev) => {
      // de-dup by id (txHash or pagingToken)
      if (prev.find((p) => p.id === n.id)) return prev;
      const next = [n, ...prev].sort(
        (left, right) => right.receivedAt - left.receivedAt,
      );
      updateStoredSyncSnapshot((snapshot) => ({
        ...snapshot,
        notifications: next,
      })).catch(() => {});
      return next;
    });
  }, []);

  const markRead = useCallback(
    async (id: string) => {
      let nextNotifications: PaymentNotification[] = [];
      setNotifications((prev) => {
        nextNotifications = prev.map((notification) =>
          notification.id === id
            ? { ...notification, read: true }
            : notification,
        );
        return nextNotifications;
      });

      await persistAndBadge(nextNotifications);
    },
    [persistAndBadge],
  );

  const markAllRead = useCallback(async () => {
    let nextNotifications: PaymentNotification[] = [];
    setNotifications((prev) => {
      nextNotifications = prev.map((notification) => ({
        ...notification,
        read: true,
      }));
      return nextNotifications;
    });

    await persistAndBadge(nextNotifications);

    // Keep in-app inbox + backend aligned for cross-device badge accuracy.
    await markInboxAllAsRead().catch(async () => {
      await syncMarkAllNotificationsRead(currentAccountId);
    });
    setInboxUnreadCount(0);
  }, [currentAccountId, persistAndBadge]);

  const syncNow = useCallback(async () => {
    setIsSyncing(true);
    try {
      await flushNotificationReadQueue();
      const result = await performBackgroundSync(
        isHydrated ? "manual" : "app-launch",
      );
      setNotifications(result.snapshot.notifications);
      setRecentActivity(result.snapshot.recentActivity);
      setCurrentAccountId(result.snapshot.currentAccountId);
      setLastSyncedAt(result.snapshot.lastSuccessfulSyncAt);
      await refreshInboxUnreadCount();
    } finally {
      setIsSyncing(false);
    }
  }, [isHydrated, refreshInboxUnreadCount]);

  const setBackgroundSyncSettings = useCallback(
    async (
      updater:
        | BackgroundSyncSettings
        | ((current: BackgroundSyncSettings) => BackgroundSyncSettings),
    ) => {
      const nextSettings =
        typeof updater === "function"
          ? updater(backgroundSyncSettings)
          : updater;

      setBackgroundSyncSettingsState(nextSettings);
      await saveBackgroundSyncSettings(nextSettings);

      const taskState = await configureBackgroundSyncTask(nextSettings);
      setBackgroundTaskAvailable(taskState.available);

      const paymentUnread = notifications.filter(
        (notification) => !notification.read,
      ).length;
      await syncAppBadgeCount(
        Math.max(paymentUnread, inboxUnreadCount),
        nextSettings.badgeEnabled,
        true,
      );
    },
    [backgroundSyncSettings, inboxUnreadCount, notifications],
  );

  useEffect(() => {
    if (!isHydrated) return;

    void configureBackgroundSyncTask(backgroundSyncSettings).then((taskState) =>
      setBackgroundTaskAvailable(taskState.available),
    );
  }, [backgroundSyncSettings, isHydrated]);

  useEffect(() => {
    if (!isHydrated) return;

    const paymentUnread = notifications.filter(
      (notification) => !notification.read,
    ).length;
    void syncAppBadgeCount(
      Math.max(paymentUnread, inboxUnreadCount),
      backgroundSyncSettings.badgeEnabled,
    );
  }, [
    backgroundSyncSettings.badgeEnabled,
    inboxUnreadCount,
    isHydrated,
    notifications,
  ]);

  useEffect(() => {
    if (!isHydrated) return;

    if (
      shouldSyncOnAppForeground({
        ...DEFAULT_SYNC_SNAPSHOT,
        notifications,
        recentActivity,
        currentAccountId,
        lastSyncedAt,
        lastSuccessfulSyncAt: lastSyncedAt,
        initialSyncCompleted: true,
      })
    ) {
      void syncNow();
    }

    const subscription = AppState.addEventListener("change", (state) => {
      if (state !== "active") return;

      void flushNotificationReadQueue()
        .then(() => refreshInboxUnreadCount())
        .catch(() => {});

      if (
        shouldSyncOnAppForeground({
          ...DEFAULT_SYNC_SNAPSHOT,
          notifications,
          recentActivity,
          currentAccountId,
          lastSyncedAt,
          lastSuccessfulSyncAt: lastSyncedAt,
          initialSyncCompleted: true,
        })
      ) {
        void syncNow();
      }
    });

    return () => subscription.remove();
  }, [
    currentAccountId,
    isHydrated,
    lastSyncedAt,
    notifications,
    recentActivity,
    refreshInboxUnreadCount,
    syncNow,
  ]);

  useEffect(() => {
    if (!isHydrated) return;
    if (!backgroundSyncSettings.enabled) return;

    const intervalId = setInterval(() => {
      void performBackgroundSync("foreground").then((result) => {
        if (result.status === "updated") {
          setNotifications(result.snapshot.notifications);
          setRecentActivity(result.snapshot.recentActivity);
          setCurrentAccountId(result.snapshot.currentAccountId);
          setLastSyncedAt(result.snapshot.lastSuccessfulSyncAt);
        }
      });
    }, getForegroundSyncIntervalMs(backgroundSyncSettings));

    return () => clearInterval(intervalId);
  }, [backgroundSyncSettings, isHydrated]);

  const paymentUnread = notifications.filter(
    (notification) => !notification.read,
  ).length;
  const unreadCount = Math.max(paymentUnread, inboxUnreadCount);

  return (
    <NotificationContext.Provider
      value={{
        notifications,
        recentActivity,
        unreadCount,
        currentAccountId,
        backgroundSyncSettings,
        backgroundTaskAvailable,
        isHydrated,
        isSyncing,
        lastSyncedAt,
        addNotification,
        markRead,
        markAllRead,
        syncNow,
        setBackgroundSyncSettings,
        soundEnabled,
        setSoundEnabled,
      }}
    >
      {children}
    </NotificationContext.Provider>
  );
};

export function useNotifications() {
  const ctx = useContext(NotificationContext);
  if (!ctx)
    throw new Error(
      "useNotifications must be used within NotificationProvider",
    );
  return ctx;
}
