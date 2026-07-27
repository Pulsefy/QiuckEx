/**
 * Transaction Timeline Types
 * Canonical schema for timeline items aggregated across payments,
 * refunds, webhooks, and contract events.
 */

export type TimelineEventKind =
  | 'payment'
  | 'refund'
  | 'webhook_delivery'
  | 'contract_event';

export type TimelineEventStatus =
  | 'success'
  | 'pending'
  | 'failed'
  | 'cancelled'
  | 'dlq';

/** A single ordered timeline entry. */
export interface TimelineItem {
  /** Unique, stable identifier for this timeline entry. */
  id: string;

  /** Broad category of the event. */
  kind: TimelineEventKind;

  /** ISO-8601 timestamp used for ordering. */
  timestamp: string;

  /** Human-readable title for the event. */
  title: string;

  /** Additional human-readable detail (optional). */
  description: string | null;

  /** Outcome of the event. */
  status: TimelineEventStatus;

  /**
   * Correlation ID linking related events across services.
   * Typically the Stellar transaction hash or a QuickEx payment ID.
   */
  correlationId: string | null;

  /**
   * Receipt reference when available (tx-hash-based receipt lookup).
   */
  receiptRef: ReceiptRef | null;

  /** Source-specific metadata. Only one of these is populated. */
  paymentDetail: PaymentTimelineDetail | null;
  refundDetail: RefundTimelineDetail | null;
  webhookDetail: WebhookTimelineDetail | null;
  contractDetail: ContractTimelineDetail | null;
}

export interface ReceiptRef {
  receiptId: string;
  txHash: string;
  /** Pre-built URL for the receipt endpoint. */
  url: string;
}

export interface PaymentTimelineDetail {
  txHash: string;
  amount: string;
  asset: string;
  sender: string;
  receiver: string;
  memo: string | null;
  ledger: number | null;
  pagingToken: string | null;
}

export interface RefundTimelineDetail {
  refundId: string;
  entityType: string;
  entityId: string;
  reasonCode: string;
  actorId: string;
  refundStatus: string;
}

export interface WebhookTimelineDetail {
  webhookLogId: string;
  eventType: string;
  eventId: string;
  deliveryStatus: string;
  attempts: number;
  httpStatus: number | null;
  lastError: string | null;
  deliveredAt: string | null;
}

export interface ContractTimelineDetail {
  contractId: string;
  webhookId: string;
  webhookUrl: string;
  triggeredAt: string;
}

export interface TimelineResponse {
  txHash: string;
  items: TimelineItem[];
  /** Total count before any limit is applied. */
  total: number;
  /** Whether data sources returned partial results (for resilience). */
  isPartial: boolean;
  /** Names of sources that failed to load (only present when isPartial=true). */
  failedSources: string[];
}
