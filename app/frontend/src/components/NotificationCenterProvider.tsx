"use client";

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  INITIAL_NOTIFICATIONS,
  NOTIFICATION_STORAGE_KEY,
  sortNotifications,
  type StoredNotification,
} from "@/lib/notifications";

type NotificationCenterContextValue = {
  notifications: StoredNotification[];
  unreadCount: number;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
};

const NotificationCenterContext =
  createContext<NotificationCenterContextValue | null>(null);

function mergeStoredNotifications(
  storedNotifications: StoredNotification[],
): StoredNotification[] {
  const storedById = new Map(
    storedNotifications.map((notification) => [notification.id, notification]),
  );

  return sortNotifications(
    INITIAL_NOTIFICATIONS.map((notification) => {
      const storedNotification = storedById.get(notification.id);

      if (!storedNotification) {
        return notification;
      }

      return {
        ...notification,
        readAt: storedNotification.readAt ?? null,
      };
    }),
  );
}

export function NotificationCenterProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [notifications, setNotifications] = useState<StoredNotification[]>(
    sortNotifications(INITIAL_NOTIFICATIONS),
  );
  const [hasHydrated, setHasHydrated] = useState(false);

  useEffect(() => {
    try {
      const storedValue = window.localStorage.getItem(NOTIFICATION_STORAGE_KEY);

      if (storedValue) {
        const parsedValue = JSON.parse(storedValue) as StoredNotification[];
        setNotifications(mergeStoredNotifications(parsedValue));
      }
    } catch (error) {
      console.error("Unable to restore notifications", error);
    } finally {
      setHasHydrated(true);
    }
  }, []);

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

  const value = useMemo<NotificationCenterContextValue>(
    () => ({
      notifications,
      unreadCount,
      markAsRead: (id: string) => {
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
      },
      markAllAsRead: () => {
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
      },
    }),
    [notifications, unreadCount],
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
