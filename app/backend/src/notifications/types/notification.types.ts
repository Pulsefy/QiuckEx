// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

export type NotificationChannel = "email" | "push" | "webhook" | "telegram";

// ---------------------------------------------------------------------------
// Notification domain events
// These extend the Stellar ingestion events with classic payment/username events.
// ---------------------------------------------------------------------------

export type NotificationEventType =
  | "EscrowDeposited"
  | "EscrowWithdrawn"
  | "EscrowRefunded"
  | "payment.received"
  | "username.claimed"
  | "recurring.payment.due"
  | "recurring.payment.executed"
  | "recurring.payment.failed"
  | "recurring.payment.cancelled"
  | "recurring.link.created"
  | "recurring.link.updated"
  | "recurring.link.paused"
  | "recurring.link.resumed"
  | "recurring.link.completed";

export interface BaseNotificationPayload {
  /** The event kind — used to match against user preference filters. */
  eventType: NotificationEventType;
  /** Unique identifier for idempotency (paging_token or tx_hash). */
  eventId: string;
  /** Stellar public key of the recipient user. */
  recipientPublicKey: string;
  /** Human-readable title shown in push/email subject. */
  title: string;
  /** Human-readable body. */
  body: string;
  /** ISO timestamp of the originating event. */
  occurredAt: string;
  /** Optional amount in stroops (used for threshold filtering). */
  amountStroops?: bigint;
  /** Arbitrary extra context for provider templates. */
  metadata?: Record<string, unknown>;
}

export interface EscrowDepositedPayload extends BaseNotificationPayload {
  eventType: "EscrowDeposited";
  commitment: string;
  token: string;
  amountStroops: bigint;
}

export interface EscrowWithdrawnPayload extends BaseNotificationPayload {
  eventType: "EscrowWithdrawn";
  commitment: string;
  token: string;
  amountStroops: bigint;
}

// ---------------------------------------------------------------------------
// Recurring Payment Notification Payloads
// ---------------------------------------------------------------------------

export interface RecurringPaymentDuePayload extends BaseNotificationPayload {
  eventType: "recurring.payment.due";
  linkId: string;
  executionId: string;
  username?: string;
  destination?: string;
  amount: number;
  asset: string;
  periodNumber: number;
  scheduledAt: string;
}

export interface RecurringPaymentExecutedPayload extends BaseNotificationPayload {
  eventType: "recurring.payment.executed";
  linkId: string;
  executionId: string;
  username?: string;
  destination?: string;
  amount: number;
  asset: string;
  periodNumber: number;
  transactionHash: string;
}

export interface RecurringPaymentFailedPayload extends BaseNotificationPayload {
  eventType: "recurring.payment.failed";
  linkId: string;
  executionId: string;
  username?: string;
  destination?: string;
  amount: number;
  asset: string;
  periodNumber: number;
  failureReason: string;
  retryCount: number;
  permanent: boolean;
}

export interface RecurringLinkStatusPayload extends BaseNotificationPayload {
  eventType: NotificationEventType;
  linkId: string;
  username?: string;
  destination?: string;
  status: string;
}

export interface EscrowRefundedPayload extends BaseNotificationPayload {
  eventType: "EscrowRefunded";
  commitment: string;
  token: string;
  amountStroops: bigint;
}

export interface PaymentReceivedPayload extends BaseNotificationPayload {
  eventType: "payment.received";
  txHash: string;
  sender: string;
  amountStroops: bigint;
}

export interface UsernameClaimedPayload extends BaseNotificationPayload {
  eventType: "username.claimed";
  username: string;
}

export type NotificationPayload =
  | EscrowDepositedPayload
  | EscrowWithdrawnPayload
  | EscrowRefundedPayload
  | PaymentReceivedPayload
  | UsernameClaimedPayload;

// ---------------------------------------------------------------------------
// User preferences
// ---------------------------------------------------------------------------

export interface NotificationPreference {
  id: string;
  publicKey: string;
  channel: NotificationChannel;
  email?: string;
  pushToken?: string;
  webhookUrl?: string;
  /** null = all events; otherwise only listed event types trigger notifications */
  events: NotificationEventType[] | null;
  minAmountStroops: bigint;
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// Delivery log
// ---------------------------------------------------------------------------

export type DeliveryStatus = "pending" | "sent" | "failed";

export interface NotificationLogEntry {
  id: string;
  publicKey: string;
  channel: NotificationChannel;
  eventType: NotificationEventType;
  eventId: string;
  status: DeliveryStatus;
  attempts: number;
  lastError?: string;
  providerMessageId?: string;
  createdAt: string;
  updatedAt: string;
}
