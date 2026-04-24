export interface Notification {
  id: string;
  title: string;
  message: string;
  type: 'payment' | 'escrow' | 'system';
  read: boolean;
  createdAt: number;
  data?: {
    transactionId?: string;
    amount?: string;
    sender?: string;
    recipient?: string;
    escrowId?: string;
  };
}

export type NotificationFilter = 'all' | 'payment' | 'escrow' | 'system';

export interface NotificationsState {
  notifications: Notification[];
  unreadCount: number;
  filter: NotificationFilter;
}
