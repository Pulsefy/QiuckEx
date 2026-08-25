/**
 * SEP-24 Transaction Repository
 *
 * Data-access layer for the `sep24_transactions` Supabase table.
 * Provides idempotent upserts and targeted status-update helpers used by
 * the SEP-24 polling service.
 */

import { Injectable, Logger } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import {
  Sep24InternalStatus,
  Sep24TransactionRecord,
  IN_FLIGHT_ANCHOR_STATUSES,
  Sep24AnchorStatus,
} from './types/sep24.types';

/** Paginated result for listing transactions. */
export interface Sep24TransactionPage {
  items: Sep24TransactionRecord[];
  total: number;
  hasMore: boolean;
}

@Injectable()
export class Sep24TransactionRepository {
  private readonly logger = new Logger(Sep24TransactionRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  // ─── Write operations ──────────────────────────────────────────────────────

  /**
   * Persist a newly-initiated SEP-24 transaction.
   *
   * Idempotent — a duplicate `anchor_transaction_id` returns the existing row.
   */
  async create(record: Omit<Sep24TransactionRecord, 'id' | 'created_at' | 'updated_at' | 'last_polled_at' | 'poll_failure_count' | 'failure_reason' | 'terminal_at'>): Promise<Sep24TransactionRecord | null> {
    const now = new Date().toISOString();

    const { data, error } = await this.supabase
      .getClient()
      .from('sep24_transactions')
      .upsert(
        {
          ...record,
          created_at: now,
          updated_at: now,
          last_polled_at: null,
          poll_failure_count: 0,
          failure_reason: null,
          terminal_at: null,
        },
        { onConflict: 'anchor_transaction_id', ignoreDuplicates: true },
      )
      .select()
      .maybeSingle();

    if (error) {
      this.logger.error(
        `Failed to create SEP-24 transaction ${record.anchor_transaction_id}: ${error.message}`,
      );
      return null;
    }

    return data as Sep24TransactionRecord | null;
  }

  /**
   * Update internal status, anchor-reported status, and last-polled timestamp
   * for a single transaction.
   */
  async updateStatus(
    id: string,
    internalStatus: Sep24InternalStatus,
    anchorStatus: string | null,
    stellarTxHash: string | null,
    opts?: { failureReason?: string; terminalAt?: string },
  ): Promise<void> {
    const now = new Date().toISOString();

    const { error } = await this.supabase
      .getClient()
      .from('sep24_transactions')
      .update({
        status: internalStatus,
        anchor_status: anchorStatus,
        stellar_tx_hash: stellarTxHash,
        last_polled_at: now,
        updated_at: now,
        failure_reason: opts?.failureReason ?? null,
        terminal_at: opts?.terminalAt ?? null,
        poll_failure_count: 0, // Reset failure counter on a successful poll
      })
      .eq('id', id);

    if (error) {
      this.logger.error(
        `Failed to update status for SEP-24 transaction ${id}: ${error.message}`,
      );
    }
  }

  /**
   * Increment the poll failure counter (used for backoff / stuck detection).
   * Does not update `last_polled_at` so the next cycle retries immediately.
   */
  async incrementPollFailures(id: string, reason: string): Promise<void> {
    // First fetch current count so we can increment it
    const { data, error: fetchErr } = await this.supabase
      .getClient()
      .from('sep24_transactions')
      .select('poll_failure_count')
      .eq('id', id)
      .maybeSingle();

    if (fetchErr || !data) {
      this.logger.warn(`Could not fetch poll_failure_count for ${id}: ${fetchErr?.message}`);
      return;
    }

    const newCount = (data as { poll_failure_count: number }).poll_failure_count + 1;

    const { error } = await this.supabase
      .getClient()
      .from('sep24_transactions')
      .update({
        poll_failure_count: newCount,
        failure_reason: reason,
        updated_at: new Date().toISOString(),
      })
      .eq('id', id);

    if (error) {
      this.logger.error(
        `Failed to increment poll failures for ${id}: ${error.message}`,
      );
    }
  }

  /**
   * Flag a transaction as stuck and remove it from active polling
   * by setting its status to `stuck_flagged`.
   */
  async flagAsStuck(id: string, reason: string): Promise<void> {
    const now = new Date().toISOString();

    const { error } = await this.supabase
      .getClient()
      .from('sep24_transactions')
      .update({
        status: Sep24InternalStatus.StuckFlagged,
        failure_reason: reason,
        updated_at: now,
        terminal_at: now,
      })
      .eq('id', id);

    if (error) {
      this.logger.error(
        `Failed to flag SEP-24 transaction ${id} as stuck: ${error.message}`,
      );
    }
  }

  /**
   * Mark a transaction as reconciled after on-chain settlement was verified.
   */
  async markReconciled(id: string): Promise<void> {
    const { error } = await this.supabase
      .getClient()
      .from('sep24_transactions')
      .update({
        status: Sep24InternalStatus.Reconciled,
        updated_at: new Date().toISOString(),
      })
      .eq('id', id);

    if (error) {
      this.logger.error(
        `Failed to mark SEP-24 transaction ${id} as reconciled: ${error.message}`,
      );
    }
  }

  // ─── Read operations ───────────────────────────────────────────────────────

  /**
   * Fetch all in-flight transactions eligible for the next poll cycle.
   *
   * "In-flight" means status in (initiated, pending) and poll_failure_count
   * below the provided maximum.
   *
   * @param limit         - Maximum rows to return.
   * @param maxFailures   - Exclude rows with poll_failure_count >= maxFailures.
   */
  async findInFlight(limit: number, maxFailures: number): Promise<Sep24TransactionRecord[]> {
    const { data, error } = await this.supabase
      .getClient()
      .from('sep24_transactions')
      .select('*')
      .in('status', [Sep24InternalStatus.Initiated, Sep24InternalStatus.Pending])
      .lt('poll_failure_count', maxFailures)
      .order('last_polled_at', { ascending: true, nullsFirst: true })
      .limit(limit);

    if (error) {
      this.logger.error(`Failed to fetch in-flight SEP-24 transactions: ${error.message}`);
      return [];
    }

    return (data ?? []) as Sep24TransactionRecord[];
  }

  /**
   * Find all in-flight transactions that have been pending longer than
   * `stuckThresholdMs` milliseconds.
   */
  async findStuck(stuckThresholdMs: number, limit: number): Promise<Sep24TransactionRecord[]> {
    const cutoff = new Date(Date.now() - stuckThresholdMs).toISOString();

    const { data, error } = await this.supabase
      .getClient()
      .from('sep24_transactions')
      .select('*')
      .in('status', [Sep24InternalStatus.Initiated, Sep24InternalStatus.Pending])
      .lt('created_at', cutoff)
      .order('created_at', { ascending: true })
      .limit(limit);

    if (error) {
      this.logger.error(`Failed to fetch stuck SEP-24 transactions: ${error.message}`);
      return [];
    }

    return (data ?? []) as Sep24TransactionRecord[];
  }

  /** Find a single transaction by its internal UUID. */
  async findById(id: string): Promise<Sep24TransactionRecord | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from('sep24_transactions')
      .select('*')
      .eq('id', id)
      .maybeSingle();

    if (error) {
      this.logger.error(`Failed to fetch SEP-24 transaction ${id}: ${error.message}`);
      return null;
    }

    return data as Sep24TransactionRecord | null;
  }

  /** Find by the anchor-assigned transaction ID. */
  async findByAnchorTransactionId(anchorTransactionId: string): Promise<Sep24TransactionRecord | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from('sep24_transactions')
      .select('*')
      .eq('anchor_transaction_id', anchorTransactionId)
      .maybeSingle();

    if (error) {
      this.logger.error(
        `Failed to fetch SEP-24 transaction by anchor id ${anchorTransactionId}: ${error.message}`,
      );
      return null;
    }

    return data as Sep24TransactionRecord | null;
  }

  /**
   * List transactions for a specific user account, newest first.
   */
  async listByUserAccount(
    userAccount: string,
    limit: number,
    offset: number,
  ): Promise<Sep24TransactionPage> {
    const effectiveLimit = Math.min(100, Math.max(1, limit));

    const { data, error, count } = await this.supabase
      .getClient()
      .from('sep24_transactions')
      .select('*', { count: 'exact' })
      .eq('user_account', userAccount)
      .order('created_at', { ascending: false })
      .range(offset, offset + effectiveLimit - 1);

    if (error) {
      this.logger.error(
        `Failed to list SEP-24 transactions for ${userAccount}: ${error.message}`,
      );
      return { items: [], total: 0, hasMore: false };
    }

    const total = count ?? 0;
    return {
      items: (data ?? []) as Sep24TransactionRecord[],
      total,
      hasMore: offset + effectiveLimit < total,
    };
  }

  /**
   * Map an anchor status string to the canonical Sep24AnchorStatus enum value.
   * Unknown strings are mapped to Sep24AnchorStatus.Unknown for forward-
   * compatibility without throwing.
   */
  static parseAnchorStatus(raw: string | null | undefined): Sep24AnchorStatus {
    if (!raw) return Sep24AnchorStatus.Unknown;

    const known = Object.values(Sep24AnchorStatus) as string[];
    return known.includes(raw) ? (raw as Sep24AnchorStatus) : Sep24AnchorStatus.Unknown;
  }

  /**
   * Derive the internal status from an anchor status.
   */
  static toInternalStatus(anchor: Sep24AnchorStatus): Sep24InternalStatus {
    switch (anchor) {
      case Sep24AnchorStatus.Completed:
        return Sep24InternalStatus.Completed;
      case Sep24AnchorStatus.Refunded:
        return Sep24InternalStatus.Refunded;
      case Sep24AnchorStatus.Expired:
        return Sep24InternalStatus.Expired;
      case Sep24AnchorStatus.Error:
      case Sep24AnchorStatus.AnchorError:
        return Sep24InternalStatus.Failed;
      default:
        // All in-flight / unknown statuses collapse to Pending
        return Sep24InternalStatus.Pending;
    }
  }
}
