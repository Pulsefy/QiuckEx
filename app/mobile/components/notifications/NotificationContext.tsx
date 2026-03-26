import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { PaymentNotification } from "./types/notification";

type NotificationContextShape = {
  notifications: PaymentNotification[];
  unreadCount: number;
  addNotification: (n: PaymentNotification) => void;
  markAllRead: () => void;
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
  const [notifications, setNotifications] = useState<PaymentNotification[]>([]);
  const [soundEnabled, setSoundEnabledState] = useState<boolean>(true);

  useEffect(() => {
    AsyncStorage.getItem(STORAGE_KEY)
      .then((v) => {
        if (v === "0") setSoundEnabledState(false);
        else setSoundEnabledState(true);
      })
      .catch(() => {});
  }, []);

  const setSoundEnabled = useCallback((v: boolean) => {
    setSoundEnabledState(v);
    AsyncStorage.setItem(STORAGE_KEY, v ? "1" : "0").catch(() => {});
  }, []);

  const addNotification = useCallback((n: PaymentNotification) => {
    setNotifications((prev) => {
      // de-dup by id (txHash or pagingToken)
      if (prev.find((p) => p.id === n.id)) return prev;
      return [n, ...prev];
    });
  }, []);

  const markAllRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);

  const unreadCount = useMemo(
    () => notifications.filter((n) => !n.read).length,
    [notifications],
  );

  return (
    <NotificationContext.Provider
      value={{
        notifications,
        unreadCount,
        addNotification,
        markAllRead,
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
