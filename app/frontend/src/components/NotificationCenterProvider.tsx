"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  NOTIFICATION_STORAGE_KEY,
  sortNotifications,
  type StoredNotification,
} from "@/lib/notifications";
import {
  fetchNotifications,
  markAllNotificationsRead,
  markNotificationRead,
} from "@/lib/notificationsApi";

type NotificationCenterContextValue = {
  notifications: StoredNotification[];
  unreadCount: number;
  /** True while the initial backend fetch is in flight. */
  isLoading: boolean;
  /** True when the backend call failed and no live data is available. */
  degraded: boolean;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  /** Re-fetch the notification list from the backend. */
  refresh: () => void;
};

const NotificationCenterContext =
  createContext<NotificationCenterContextValue | null>(null);

/**
 * Applies locally persisted read-state on top of live backend notifications.
 * The backend is the source of truth for the list itself; localStorage only
 * remembers read timestamps so optimistic updates survive a refresh.
 */
function applyStoredReadState(
  notifications: StoredNotification[],
  storedNotifications: StoredNotification[],
): StoredNotification[] {
  const storedById = new Map(
    storedNotifications.map((notification) => [notification.id, notification]),
  );

  return sortNotifications(
    notifications.map((notification) => {
      const storedNotification = storedById.get(notification.id);

      if (!storedNotification) {
        return notification;
      }

      return {
        ...notification,
        readAt: notification.readAt ?? storedNotification.readAt ?? null,
      };
    }),
  );
}

function readStoredNotifications(): StoredNotification[] {
  try {
    const storedValue = window.localStorage.getItem(NOTIFICATION_STORAGE_KEY);

    if (!storedValue) {
      return [];
    }

    const parsedValue = JSON.parse(storedValue) as StoredNotification[];
    return Array.isArray(parsedValue) ? parsedValue : [];
  } catch (error) {
    console.error("Unable to restore notifications", error);
    return [];
  }
}

export function NotificationCenterProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [notifications, setNotifications] = useState<StoredNotification[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [degraded, setDegraded] = useState(false);
  const [hasHydrated, setHasHydrated] = useState(false);
  const storedNotificationsRef = useRef<StoredNotification[]>([]);

  const loadNotifications = useCallback(async () => {
    setIsLoading(true);

    const { notifications: liveNotifications, degraded: isDegraded } =
      await fetchNotifications();

    setDegraded(isDegraded);
    setNotifications(
      applyStoredReadState(liveNotifications, storedNotificationsRef.current),
    );
    setIsLoading(false);
  }, []);

  useEffect(() => {
    storedNotificationsRef.current = readStoredNotifications();
    setHasHydrated(true);
    void loadNotifications();
  }, [loadNotifications]);

  useEffect(() => {
    if (!hasHydrated) {
      return;
    }

    window.localStorage.setItem(
      NOTIFICATION_STORAGE_KEY,
      JSON.stringify(notifications),
    );
  }, [hasHydrated, notifications]);

  const unreadCount = useMemo(
    () =>
      notifications.filter((notification) => notification.readAt === null)
        .length,
    [notifications],
  );

  const markAsRead = useCallback((id: string) => {
    setNotifications((currentNotifications) =>
      sortNotifications(
        currentNotifications.map((notification) =>
          notification.id === id && notification.readAt === null
            ? {
                ...notification,
                readAt: new Date().toISOString(),
              }
            : notification,
        ),
      ),
    );

    void markNotificationRead(id).catch((error) => {
      console.warn("Unable to sync notification read state with backend", error);
    });
  }, []);

  const markAllAsRead = useCallback(() => {
    setNotifications((currentNotifications) =>
      sortNotifications(
        currentNotifications.map((notification) =>
          notification.readAt === null
            ? {
                ...notification,
                readAt: new Date().toISOString(),
              }
            : notification,
        ),
      ),
    );

    void markAllNotificationsRead().catch((error) => {
      console.warn("Unable to sync notification read state with backend", error);
    });
  }, []);

  const refresh = useCallback(() => {
    void loadNotifications();
  }, [loadNotifications]);

  const value = useMemo<NotificationCenterContextValue>(
    () => ({
      notifications,
      unreadCount,
      isLoading,
      degraded,
      markAsRead,
      markAllAsRead,
      refresh,
    }),
    [
      notifications,
      unreadCount,
      isLoading,
      degraded,
      markAsRead,
      markAllAsRead,
      refresh,
    ],
  );

  return (
    <NotificationCenterContext.Provider value={value}>
      {children}
    </NotificationCenterContext.Provider>
  );
}

export function useNotificationCenter() {
  const context = useContext(NotificationCenterContext);

  if (!context) {
    throw new Error(
      "useNotificationCenter must be used inside NotificationCenterProvider.",
    );
  }

  return context;
}
