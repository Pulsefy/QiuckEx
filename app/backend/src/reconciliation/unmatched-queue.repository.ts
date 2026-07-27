import { Injectable, Logger } from '@nestjs/common';

import { SupabaseService } from '../supabase/supabase.service';
import {
  IncomingTransaction,
  UnmatchedTransaction,
  UnmatchedStatus,
} from './types/auto-match.types';

/** Paginated result returned by {@link UnmatchedQueueRepository.listPending}. */
export interface UnmatchedPage {
  items: UnmatchedTransaction[];
  total: number;
  hasMore: boolean;
}

/**
 * UnmatchedQueueRepository
 *
 * Data-access layer for the `unmatched_transactions` table.
 * Transactions land here when the auto-match engine cannot find a payment link
 * with sufficient confidence.  Operators review, resolve, or dismiss entries
 * via the admin endpoints on ReconciliationController.
 */
@Injectable()
export class UnmatchedQueueRepository {
  private readonly logger = new Logger(UnmatchedQueueRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  /**
   * Persist an incoming transaction in the review queue.
   *
   * Idempotent — a duplicate `tx_hash` is silently ignored (the existing row
   * is returned as-is).  This ensures the cron-based engine can safely retry
   * without creating duplicates.
   */
  async enqueue(
    tx: IncomingTransaction,
    bestCandidateLinkId: string | null,
    bestConfidence: number | null,
  ): Promise<UnmatchedTransaction | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from('unmatched_transactions')
      .upsert(
        {
          tx_hash: tx.txHash,
          ledger: tx.ledger,
          source_account: tx.sourceAccount,
          destination_account: tx.destinationAccount,
          amount: tx.amount,
          asset_code: tx.assetCode,
          asset_issuer: tx.assetIssuer ?? null,
          memo: tx.memo ?? null,
          memo_type: tx.memoType ?? null,
          occurred_at: tx.occurredAt,
          best_candidate_link_id: bestCandidateLinkId,
          best_confidence: bestConfidence,
        },
        { onConflict: 'tx_hash', ignoreDuplicates: true },
      )
      .select()
      .maybeSingle();

    if (error) {
      this.logger.error(
        `Failed to enqueue unmatched transaction ${tx.txHash}: ${error.message}`,
      );
      return null;
    }

    return (data as UnmatchedTransaction | null);
  }

  /**
   * Return a page of pending (unreviewed) transactions, newest first.
   *
   * @param limit  - Max rows to return (capped at 100).
   * @param offset - Zero-based row offset for pagination.
   */
  async listPending(limit: number, offset: number): Promise<UnmatchedPage> {
    const effectiveLimit = Math.min(100, Math.max(1, limit));

    const { data, error, count } = await this.supabase
      .getClient()
      .from('unmatched_transactions')
      .select('*', { count: 'exact' })
      .eq('status', UnmatchedStatus.Pending)
      .order('ingested_at', { ascending: false })
      .range(offset, offset + effectiveLimit - 1);

    if (error) {
      this.logger.error(`Failed to list unmatched transactions: ${error.message}`);
      return { items: [], total: 0, hasMore: false };
    }

    const total = count ?? 0;
    return {
      items: (data ?? []) as UnmatchedTransaction[],
      total,
      hasMore: offset + effectiveLimit < total,
    };
  }

  /** Look up a single row by its UUID primary key. */
  async findById(id: string): Promise<UnmatchedTransaction | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from('unmatched_transactions')
      .select('*')
      .eq('id', id)
      .maybeSingle();

    if (error) {
      this.logger.error(`Failed to find unmatched transaction ${id}: ${error.message}`);
      return null;
    }

    return (data as UnmatchedTransaction | null);
  }

  /** Look up a single row by Stellar transaction hash. */
  async findByTxHash(txHash: string): Promise<UnmatchedTransaction | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from('unmatched_transactions')
      .select('*')
      .eq('tx_hash', txHash)
      .maybeSingle();

    if (error) {
      this.logger.error(`Failed to find unmatched tx by hash ${txHash}: ${error.message}`);
      return null;
    }

    return (data as UnmatchedTransaction | null);
  }

  /**
   * Mark an entry as resolved after an operator manually confirms which
   * payment link this transaction belongs to.
   *
   * Only rows with `status = 'pending'` are updated; this guards against
   * accidentally re-resolving an already-handled entry.
   *
   * @throws Error if the database update fails.
   */
  async resolve(id: string, resolvedBy: string, note?: string): Promise<void> {
    const { error } = await this.supabase
      .getClient()
      .from('unmatched_transactions')
      .update({
        status: UnmatchedStatus.Resolved,
        resolved_by: resolvedBy,
        resolved_at: new Date().toISOString(),
        resolution_note: note ?? null,
      })
      .eq('id', id)
      .eq('status', UnmatchedStatus.Pending);

    if (error) {
      this.logger.error(`Failed to resolve unmatched transaction ${id}: ${error.message}`);
      throw new Error(`Could not resolve unmatched transaction ${id}: ${error.message}`);
    }
  }

  /**
   * Dismiss an entry — the operator has determined this transaction does not
   * correspond to any QuickEx payment link and requires no further action.
   *
   * @throws Error if the database update fails.
   */
  async dismiss(id: string, resolvedBy: string, note?: string): Promise<void> {
    const { error } = await this.supabase
      .getClient()
      .from('unmatched_transactions')
      .update({
        status: UnmatchedStatus.Dismissed,
        resolved_by: resolvedBy,
        resolved_at: new Date().toISOString(),
        resolution_note: note ?? null,
      })
      .eq('id', id)
      .eq('status', UnmatchedStatus.Pending);

    if (error) {
      this.logger.error(`Failed to dismiss unmatched transaction ${id}: ${error.message}`);
      throw new Error(`Could not dismiss unmatched transaction ${id}: ${error.message}`);
    }
  }
}
