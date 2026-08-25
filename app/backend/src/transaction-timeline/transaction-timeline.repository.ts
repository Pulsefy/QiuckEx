/**
 * Transaction timeline repository port.
 *
 * Defines the persistence contract for the database-backed sources aggregated
 * by `TransactionTimelineService` (payment records, refund attempts, webhook
 * notification logs, and contract change webhooks). The service depends on the
 * `TransactionTimelineRepository` interface (via the
 * `TRANSACTION_TIMELINE_REPOSITORY` DI token) rather than on Supabase directly.
 *
 * The Supabase-backed adapter lives in the same file as the concrete
 * `SupabaseTransactionTimelineRepository`.
 */

import { Injectable, Logger } from '@nestjs/common';

import { SupabaseService } from '../supabase/supabase.service';

export interface TimelinePaymentRecordRow {
  id: string;
  status: string | null;
  created_at: string;
  amount: string | number | null;
  asset_code: string | null;
  sender_address: string | null;
  receiver_address: string | null;
}

export interface TimelineRefundAttemptRow {
  id: string;
  entity_type: string | null;
  entity_id: string | null;
  reason_code: string | null;
  status: string | null;
  actor_id: string | null;
  created_at: string;
}

export interface TimelineNotificationLogRow {
  id: string;
  event_type: string | null;
  event_id: string | null;
  status: string | null;
  attempts: number | null;
  last_error: string | null;
  webhook_response_status: number | null;
  webhook_delivered_at: string | null;
  created_at: string;
}

export interface TimelineContractWebhookRow {
  id: string;
  webhook_url: string | null;
  enabled: boolean | null;
  created_at: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Port
// ---------------------------------------------------------------------------

export interface TransactionTimelineRepository {
  /** Payment records matching a transaction hash (fallback when no address). */
  getPaymentRecordsByTxHash(txHash: string): Promise<TimelinePaymentRecordRow[]>;

  /** Refund attempts correlated with a transaction hash. */
  getRefundAttempts(txHash: string): Promise<TimelineRefundAttemptRow[]>;

  /** Webhook delivery notification logs for a public key / tx hash. */
  getNotificationLogs(
    txHash: string,
    publicKey: string,
    limit?: number,
  ): Promise<TimelineNotificationLogRow[]>;

  /** Enabled contract change webhooks (best-effort contract signal). */
  getEnabledContractWebhooks(limit?: number): Promise<TimelineContractWebhookRow[]>;
}

export const TRANSACTION_TIMELINE_REPOSITORY = Symbol(
  'TRANSACTION_TIMELINE_REPOSITORY',
);

// ---------------------------------------------------------------------------
// Supabase adapter
// ---------------------------------------------------------------------------

@Injectable()
export class SupabaseTransactionTimelineRepository
  implements TransactionTimelineRepository
{
  private readonly logger = new Logger(SupabaseTransactionTimelineRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  async getPaymentRecordsByTxHash(
    txHash: string,
  ): Promise<TimelinePaymentRecordRow[]> {
    const client = this.supabase.getClient();
    const { data, error } = await client
      .from('payment_records')
      .select('id, status, created_at, amount, asset_code, sender_address, receiver_address')
      .eq('tx_hash', txHash);

    if (error) throw error;
    return (data ?? []) as TimelinePaymentRecordRow[];
  }

  async getRefundAttempts(txHash: string): Promise<TimelineRefundAttemptRow[]> {
    const client = this.supabase.getClient();
    const { data, error } = await client
      .from('refund_attempts')
      .select('id, entity_type, entity_id, reason_code, status, actor_id, created_at')
      .or(`entity_id.eq.${txHash},id.eq.${txHash}`);

    if (error) throw error;
    return (data ?? []) as TimelineRefundAttemptRow[];
  }

  async getNotificationLogs(
    txHash: string,
    publicKey: string,
    limit = 50,
  ): Promise<TimelineNotificationLogRow[]> {
    const client = this.supabase.getClient();
    const { data, error } = await client
      .from('notification_log')
      .select(
        'id, event_type, event_id, status, attempts, last_error, webhook_response_status, webhook_delivered_at, created_at',
      )
      .eq('public_key', publicKey)
      .eq('channel', 'webhook')
      .ilike('event_id', `%${txHash}%`)
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) throw error;
    return (data ?? []) as TimelineNotificationLogRow[];
  }

  async getEnabledContractWebhooks(
    limit = 10,
  ): Promise<TimelineContractWebhookRow[]> {
    const client = this.supabase.getClient();
    const { data, error } = await client
      .from('contract_change_webhooks')
      .select('id, webhook_url, enabled, created_at, updated_at')
      .eq('enabled', true)
      .order('updated_at', { ascending: false })
      .limit(limit);

    if (error) {
      // Table may not exist yet in all environments — degrade gracefully
      this.logger.debug(
        `contract_change_webhooks query failed: ${error.message}`,
      );
      return [];
    }

    return (data ?? []) as TimelineContractWebhookRow[];
  }
}
