import { NotificationEventType } from "../types/notification.types";

export interface InAppNotification {
  id: string;
  publicKey: string;
  eventType: NotificationEventType;
  eventId: string;
  title: string;
  body: string;
  read: boolean;
  metadata?: Record<string, unknown>;
  createdAt: string;
}