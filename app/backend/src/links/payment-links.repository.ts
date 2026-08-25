/**
 * Payment links repository port.
 *
 * Defines the persistence contract for payment-link related data access used by
 * `PaymentLinkService` and `PaymentLinkExpiryService`. Services depend on the
 * `PaymentLinksRepository` interface (via the `PAYMENT_LINKS_REPOSITORY` DI
 * token) instead of a concrete storage implementation.
 *
 * The Supabase-backed adapter lives in the same file as the concrete
 * `SupabasePaymentLinksRepository`.
 */

import { Injectable, Logger } from '@nestjs/common';

import { SupabaseService } from '../supabase/supabase.service';

export interface ExpiredPaymentLinkRow {
  id: string;
  owner_public_key: string | null;
  destination_public_key: string | null;
  amount: string | number;
  asset_code: string | null;
  memo: string | null;
  expires_at: string | null;
  matched_tx_hash: string | null;
  matched_at: string | null;
}

export interface PaymentLinkExpiryAuditRow {
  linkId: string;
  previousStatus: 'open' | string;
  newStatus: 'expired' | string;
  expiresAt: string | null;
  processedAt: string;
  processedBy: string;
  runId: string;
  note: string;
}

// ---------------------------------------------------------------------------
// Port
// ---------------------------------------------------------------------------

export interface PaymentLinksRepository {
  /**
   * Resolve the destination public key for a username, or null if unknown.
   */
  getPublicKeyByUsername(username: string): Promise<string | null>;

  /**
   * Mark open payment_links whose `expires_at` <= now as expired and return
   * the affected rows so callers can audit and emit events. Idempotent and
   * replay-safe: the update is constrained to rows with status='open'.
   */
  markExpiredLinks(
    nowIso: string,
    runId: string,
  ): Promise<ExpiredPaymentLinkRow[]>;

  /**
   * Persist an audit record for an expired payment link.
   */
  insertExpiryAudit(row: PaymentLinkExpiryAuditRow): Promise<void>;
}

export const PAYMENT_LINKS_REPOSITORY = Symbol('PAYMENT_LINKS_REPOSITORY');

// ---------------------------------------------------------------------------
// Supabase adapter
// ---------------------------------------------------------------------------

@Injectable()
export class SupabasePaymentLinksRepository implements PaymentLinksRepository {
  private readonly logger = new Logger(SupabasePaymentLinksRepository.name);

  constructor(private readonly supabaseService: SupabaseService) {}

  async getPublicKeyByUsername(username: string): Promise<string | null> {
    const { data, error } = await this.supabaseService
      .getClient()
      .from('usernames')
      .select('public_key')
      .eq('username', username.toLowerCase())
      .single();

    if (error || !data) {
      return null;
    }

    return data.public_key as string;
  }

  async markExpiredLinks(
    nowIso: string,
    runId: string,
  ): Promise<ExpiredPaymentLinkRow[]> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from('payment_links')
      .update({
        status: 'expired',
        expiry_processed_at: nowIso,
        expiry_processed_by: 'expiry-worker',
        expiry_note: `expired by sweep ${runId}`,
      })
      .eq('status', 'open')
      .not('expires_at', 'is', null)
      .lte('expires_at', nowIso)
      .select(
        'id,owner_public_key,destination_public_key,amount,asset_code,memo,expires_at,matched_tx_hash,matched_at',
      );

    if (error) {
      this.logger.error(`Failed to mark expired links: ${error.message}`);
      return [];
    }

    return (data ?? []) as ExpiredPaymentLinkRow[];
  }

  async insertExpiryAudit(row: PaymentLinkExpiryAuditRow): Promise<void> {
    const client = this.supabaseService.getClient();
    const { error } = await client.from('payment_link_expiry_audit').insert({
      link_id: row.linkId,
      previous_status: row.previousStatus,
      new_status: row.newStatus,
      expires_at: row.expiresAt,
      processed_at: row.processedAt,
      processed_by: row.processedBy,
      run_id: row.runId,
      note: row.note,
    });

    if (error) {
      this.logger.warn(
        `Failed to record expiry audit for ${row.linkId}: ${error.message}`,
      );
    }
  }
}
