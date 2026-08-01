/**
 * Dashboard Activity Feed Types
 *
 * Canonical schema for dashboard activity feed items aggregated across
 * payments, refunds, webhook deliveries, in-app notifications, and
 * contract events.
 */

export type FeedItemKind =
  | 'payment'
  | 'refund'
  | 'webhook_delivery'
  | 'notification'
  | 'contract_event'
  | 'username_action';

export type FeedItemStatus =
  | 'success'
  | 'pending'
  | 'failed'
  | 'cancelled'
  | 'dlq'
  | 'unread'
  | 'read';

/** A single unified activity feed entry. */
export interface FeedItem {
  /** Unique, stable identifier for this feed entry. */
  id: string;

  /** Broad category of the event. */
  kind: FeedItemKind;

  /** ISO-8601 timestamp used for ordering (created_at from source table). */
  timestamp: string;

  /** Human-readable title for the event. */
  title: string;

  /** Additional human-readable detail. */
  description: string | null;

  /** Outcome of the event. */
  status: FeedItemStatus;

  /**
   * Correlation ID linking related events across services.
   * Typically the Stellar transaction hash or a QuickEx payment ID.
   */
  correlationId: string | null;

  /** Source-specific metadata. Only one of these is populated per item. */
  paymentDetail: PaymentFeedDetail | null;
  refundDetail: RefundFeedDetail | null;
  webhookDetail: WebhookFeedDetail | null;
  notificationDetail: NotificationFeedDetail | null;
  contractDetail: ContractFeedDetail | null;
  usernameDetail: UsernameFeedDetail | null;
}

export interface PaymentFeedDetail {
  txHash: string;
  amount: string;
  asset: string;
  sender: string;
  receiver: string;
  status: string;
}

export interface RefundFeedDetail {
  refundId: string;
  entityType: string;
  entityId: string;
  reasonCode: string;
  refundStatus: string;
}

export interface WebhookFeedDetail {
  webhookLogId: string;
  eventType: string;
  eventId: string;
  deliveryStatus: string;
  attempts: number;
  httpStatus: number | null;
  lastError: string | null;
  deliveredAt: string | null;
}

export interface NotificationFeedDetail {
  notificationId: string;
  eventType: string;
  eventId: string;
  title: string;
  body: string;
  read: boolean;
}

export interface ContractFeedDetail {
  contractWebhookId: string;
  webhookUrl: string;
  enabled: boolean;
}

export interface UsernameFeedDetail {
  username: string;
  publicKey: string;
}

export interface FeedResponse {
  data: FeedItem[];
  pagination: {
    next_cursor: string | null;
    has_more: boolean;
    limit: number;
  };
  /** Whether any data source failed to load (partial response). */
  isPartial: boolean;
  /** Names of sources that failed (only present when isPartial=true). */
  failedSources: string[];
}
