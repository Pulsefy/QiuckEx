import AsyncStorage from '@react-native-async-storage/async-storage';
import { Notification } from '../types/notification';

const NOTIFICATIONS_KEY = 'app_notifications';

// Mock notifications for testing
const MOCK_NOTIFICATIONS: Notification[] = [
  {
    id: '1',
    title: 'Payment Received',
    message: 'You received $50.00 from John Doe',
    type: 'payment',
    read: false,
    createdAt: Date.now() - 3600000,
    data: { amount: '50.00', sender: 'John Doe' }
  },
  {
    id: '2',
    title: 'Escrow Released',
    message: 'Escrow #1234 has been released successfully',
    type: 'escrow',
    read: false,
    createdAt: Date.now() - 7200000,
    data: { escrowId: '1234' }
  },
  {
    id: '3',
    title: 'Welcome to QiuckEx!',
    message: 'Thanks for joining QiuckEx. Start your crypto journey today!',
    type: 'system',
    read: true,
    createdAt: Date.now() - 86400000,
  },
];

export async function getNotifications(): Promise<Notification[]> {
  try {
    const stored = await AsyncStorage.getItem(NOTIFICATIONS_KEY);
    if (stored) {
      return JSON.parse(stored);
    }
    await AsyncStorage.setItem(NOTIFICATIONS_KEY, JSON.stringify(MOCK_NOTIFICATIONS));
    return MOCK_NOTIFICATIONS;
  } catch (error) {
    console.error('Error loading notifications:', error);
    return MOCK_NOTIFICATIONS;
  }
}

export async function saveNotifications(notifications: Notification[]): Promise<void> {
  try {
    await AsyncStorage.setItem(NOTIFICATIONS_KEY, JSON.stringify(notifications));
  } catch (error) {
    console.error('Error saving notifications:', error);
  }
}

export async function markAsRead(notificationId: string): Promise<void> {
  const notifications = await getNotifications();
  const updated = notifications.map(n => 
    n.id === notificationId ? { ...n, read: true } : n
  );
  await saveNotifications(updated);
}

export async function markAllAsRead(): Promise<void> {
  const notifications = await getNotifications();
  const updated = notifications.map(n => ({ ...n, read: true }));
  await saveNotifications(updated);
}

export async function deleteNotification(notificationId: string): Promise<void> {
  const notifications = await getNotifications();
  const updated = notifications.filter(n => n.id !== notificationId);
  await saveNotifications(updated);
}

export async function getUnreadCount(): Promise<number> {
  const notifications = await getNotifications();
  return notifications.filter(n => !n.read).length;
}
