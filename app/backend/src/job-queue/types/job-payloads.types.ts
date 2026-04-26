/**
 * Job Queue System - Job Payload Type Definitions
 * 
 * This module defines the payload interfaces for all supported job types.
 * Each job type has a specific payload structure validated at enqueue time.
 */

/**
 * Webhook delivery job payload
 * Used for delivering webhook notifications to external endpoints
 */
export interface WebhookDeliveryPayload {
  /** Public key of the notification recipient */
  recipientPublicKey: string;
  
  /** Target webhook URL to deliver to */
  webhookUrl: string;
  
  /** Type of event being delivered */
  eventType: string;
  
  /** Unique identifier for this event */
  eventId: string;
  
  /** Event-specific payload data */
  payload: Record<string, unknown>;
}

/**
 * Recurring payment job payload
 * Used for executing scheduled recurring payments on Stellar
 */
export interface RecurringPaymentPayload {
  /** ID of the recurring link configuration */
  recurringLinkId: string;
  
  /** ID of this specific execution */
  executionId: string;
  
  /** Stellar address to send payment to */
  recipientAddress: string;
  
  /** Payment amount (as string to preserve precision) */
  amount: string;
  
  /** Asset code (e.g., 'XLM', 'USDC') */
  asset: string;
  
  /** Asset issuer address (optional, not needed for native XLM) */
  assetIssuer?: string;
  
  /** Transaction memo (optional) */
  memo?: string;
  
  /** Memo type (optional, e.g., 'text', 'id', 'hash') */
  memoType?: string;
}

/**
 * Export generation job payload
 * Used for generating and delivering data exports (CSV/JSON)
 */
export interface ExportGenerationPayload {
  /** User ID requesting the export */
  userId: string;
  
  /** Type of data to export */
  exportType: 'transactions' | 'links' | 'payments';
  
  /** Filters to apply to the export query */
  filters: Record<string, unknown>;
  
  /** Output format */
  format: 'csv' | 'json';
  
  /** How to deliver the export */
  deliveryMethod: 'webhook' | 'email' | 'download';
}

/**
 * Reconciliation job payload
 * Used for comparing internal state with Stellar ledger
 */
export interface ReconciliationPayload {
  /** Number of records to process per batch */
  batchSize: number;
  
  /** Starting ledger sequence (optional) */
  startLedger?: number;
  
  /** Ending ledger sequence (optional) */
  endLedger?: number;
}

/**
 * Stellar reconnection job payload
 * Used for reconnecting SSE streams after disconnection
 */
export interface StellarReconnectPayload {
  /** Contract ID to reconnect to */
  contractId: string;
  
  /** Last cursor position before disconnection */
  lastCursor: string;
}
