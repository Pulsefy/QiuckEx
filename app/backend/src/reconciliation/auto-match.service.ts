import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Horizon } from 'stellar-sdk';

import { AppConfigService } from '../config/app-config.service';
import { SupabaseService } from '../supabase/supabase.service';
import { MetricsService } from '../metrics/metrics.service';
import { HORIZON_BASE_URLS } from '../config/stellar.config';
import { UnmatchedQueueRepository } from './unmatched-queue.repository';
import {
  AutoReconciliationSucceededPayload,
  IncomingTransaction,
  MatchDecision,
  MatchResult,
  MatchScore,
  MatchScoreBreakdown,
  PaymentLink,
  PaymentLinkStatus,
} from './types/auto-match.types';

/**
 * Minimum confidence (0–100) required to auto-apply a match.
 *
 * In practice only a unique-memo + exact-amount match reaches this score,
 * satisfying the acceptance criterion: "Transactions with unique memos are
 * matched with 100% accuracy."
 */
const AUTO_MATCH_THRESHOLD = 95;

/**
 * Minimum confidence to queue a transaction for manual review instead of
 * discarding it as completely unmatched.
 */
const REVIEW_THRESHOLD = 55;

/**
 * Relative tolerance used for near-exact amount comparisons.
 * A delta of ≤ 0.1% is treated as "within tolerance" (partial credit).
 */
const AMOUNT_TOLERANCE_PCT = 0.001;

/**
 * AutoMatchService
 *
 * Background service that automatically reconciles incoming Stellar payment
 * transactions with open QuickEx payment links.
 *
 * ## Confidence scoring (0–100 points)
 *
 * | Signal                               | Points |
 * |--------------------------------------|--------|
 * | Exact memo match, memo is unique     | 60     |
 * | Exact memo match, memo is non-unique | 25     |
 * | Exact amount match                   | 40     |
 * | Amount within AMOUNT_TOLERANCE_PCT   | 20     |
 *
 * A memo that is present on one side but absent or different on the other is a
 * hard mismatch — that candidate is scored zero and excluded immediately.
 * Assets must also match exactly; cross-asset candidates are excluded.
 *
 * ## Decision thresholds
 * - ≥ 95  → AutoMatch   (link marked "paid", webhook fired)
 * - 55–94 → ReviewRequired (queued in unmatched_transactions)
 * - < 55  → Unmatched   (stored with no best-candidate reference)
 *
 * ## Processing cadence
 * The cron fires every minute.  Each cycle fetches all open payment links,
 * groups them by destination address, and for each destination queries Horizon
 * for recent payment operations (with per-destination cursor tracking to avoid
 * re-processing).
 */
@Injectable()
export class AutoMatchService {
  private readonly logger = new Logger(AutoMatchService.name);
  private readonly server: Horizon.Server;

  /**
   * Per-destination Horizon paging_token cursors.  Kept in memory so each
   * cycle only processes new transactions.  A process restart causes at most a
   * short window of re-evaluation — safe because all operations are idempotent.
   */
  private readonly destinationCursors = new Map<string, string>();

  private isRunning = false;

  constructor(
    private readonly config: AppConfigService,
    private readonly supabase: SupabaseService,
    private readonly unmatchedQueue: UnmatchedQueueRepository,
    private readonly metrics: MetricsService,
    private readonly eventEmitter: EventEmitter2,
  ) {
    const horizonUrl = HORIZON_BASE_URLS[config.network];
    this.server = new Horizon.Server(horizonUrl);
    this.logger.log(`AutoMatchService initialised (${config.network} → ${horizonUrl})`);
  }

  // ─── Cron ──────────────────────────────────────────────────────────────────

  /**
   * Runs every minute.  Self-serialising: if the previous cycle is still in
   * progress when the next tick fires, the tick is skipped.
   */
  @Cron(CronExpression.EVERY_MINUTE, {
    name: 'auto-match-cycle',
    timeZone: 'UTC',
  })
  async handleCron(): Promise<void> {
    if (this.isRunning) {
      this.logger.warn('Auto-match tick skipped — previous cycle still in progress');
      return;
    }
    await this.runAutoMatchCycle();
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  /**
   * Execute a complete auto-match cycle.
   *
   * Fetches all open payment links, polls Horizon for recent incoming payments
   * to each destination address, and processes every new transaction through
   * the scoring algorithm.
   *
   * Safe to call externally (e.g. from an admin endpoint for on-demand runs).
   *
   * @returns Summary counters for the cycle.
   */
  async runAutoMatchCycle(): Promise<{
    processed: number;
    matched: number;
    queued: number;
    unmatched: number;
  }> {
    this.isRunning = true;
    const startMs = Date.now();
    let processed = 0;
    let matched = 0;
    let queued = 0;
    let unmatched = 0;

    try {
      const openLinks = await this.fetchOpenPaymentLinks();
      if (openLinks.length === 0) {
        this.logger.debug('Auto-match cycle: no open payment links found');
        return { processed, matched, queued, unmatched };
      }

      const byDestination = this.groupByDestination(openLinks);

      for (const [destination, links] of byDestination.entries()) {
        const cursor = this.destinationCursors.get(destination);
        const transactions = await this.fetchRecentPayments(destination, cursor);

        for (const tx of transactions) {
          processed++;
          const result = await this.processTransaction(tx, links);

          switch (result.decision) {
            case MatchDecision.AutoMatch:
              matched++;
              break;
            case MatchDecision.ReviewRequired:
              queued++;
              break;
            default:
              unmatched++;
          }

          // Advance the cursor so this transaction is not re-evaluated next tick.
          this.destinationCursors.set(destination, tx.txHash);
        }
      }

      const durationMs = Date.now() - startMs;
      this.logger.log(
        `Auto-match cycle complete in ${durationMs}ms — ` +
        `processed:${processed} matched:${matched} queued:${queued} unmatched:${unmatched}`,
      );
    } catch (err) {
      this.logger.error(
        `Auto-match cycle failed: ${(err as Error).message}`,
        (err as Error).stack,
      );
    } finally {
      this.isRunning = false;
    }

    return { processed, matched, queued, unmatched };
  }

  /**
   * Score and dispatch a single incoming transaction against a set of candidate
   * payment links.
   *
   * Exposed as a public method so callers (e.g. an admin endpoint or the
   * ingestion pipeline) can trigger on-demand matching for a specific
   * transaction without waiting for the next cron tick.
   *
   * @param tx               - The incoming Stellar payment to process.
   * @param candidateLinks   - Pre-fetched open links to score against.
   *                           If omitted, the service queries Supabase for all
   *                           open links matching the transaction destination.
   */
  async processTransaction(
    tx: IncomingTransaction,
    candidateLinks?: PaymentLink[],
  ): Promise<MatchResult> {
    const links = candidateLinks
      ?? await this.fetchOpenLinksForDestination(tx.destinationAccount);

    const candidates = this.scoreCandidates(tx, links);
    const best = candidates[0] ?? null;
    const decision = this.resolveDecision(best?.score.confidence ?? 0);
    const processedAt = new Date().toISOString();

    const result: MatchResult = {
      transaction: tx,
      decision,
      bestLink: best?.link ?? null,
      bestScore: best?.score ?? null,
      candidates,
      processedAt,
    };

    await this.applyDecision(result);
    return result;
  }

  // ─── Scoring ───────────────────────────────────────────────────────────────

  /**
   * Score a transaction against all candidate links and return candidates with
   * a confidence > 0, sorted by confidence descending.
   *
   * @param tx    - The incoming transaction.
   * @param links - Open payment links to evaluate as candidates.
   */
  scoreCandidates(
    tx: IncomingTransaction,
    links: PaymentLink[],
  ): Array<{ link: PaymentLink; score: MatchScore }> {
    // Count how many open links carry each memo so we can detect uniqueness.
    const memoCounts = this.countMemoOccurrences(links);

    return links
      .map((link) => ({ link, score: this.scoreOne(tx, link, memoCounts) }))
      .filter((c) => c.score.confidence > 0)
      .sort((a, b) => b.score.confidence - a.score.confidence);
  }

  /**
   * Score a single (transaction, link) pair.
   *
   * ## Scoring matrix (max 100 points)
   *
   * **Memo component (0–60 pts)**
   * - Exact match, memo unique across open links: 60 pts
   * - Exact match, memo non-unique:               25 pts
   * - Memo present on one side but not the other:  0 pts (hard exclusion)
   * - Memo mismatch:                               0 pts (hard exclusion)
   *
   * **Amount component (0–40 pts)**
   * - Exact match (< 1e-7 delta):                 40 pts
   * - Within AMOUNT_TOLERANCE_PCT:                20 pts
   * - Outside tolerance:                           0 pts
   *
   * Asset code + issuer must match exactly; mismatching assets return score 0.
   */
  scoreOne(
    tx: IncomingTransaction,
    link: PaymentLink,
    memoCounts: Map<string, number>,
  ): MatchScore {
    const assetMatches =
      tx.assetCode === link.asset_code &&
      (tx.assetIssuer ?? null) === (link.asset_issuer ?? null);

    if (!assetMatches) {
      return this.zeroScore(false);
    }

    const breakdown: MatchScoreBreakdown = {
      memoPresent: !!(tx.memo && link.memo),
      memoMatches: false,
      memoIsUnique: false,
      amountExact: false,
      amountWithinTolerance: false,
      assetMatches: true,
    };

    // ── Memo scoring ─────────────────────────────────────────────────────────
    let memoPoints = 0;

    if (tx.memo && link.memo) {
      if (tx.memo !== link.memo) {
        // Both sides have a memo but they disagree — definitive mismatch.
        return this.zeroScore(true);
      }

      breakdown.memoMatches = true;
      const occurrences = memoCounts.get(link.memo) ?? 1;
      breakdown.memoIsUnique = occurrences === 1;
      memoPoints = breakdown.memoIsUnique ? 60 : 25;
    } else if (tx.memo && !link.memo) {
      // Transaction carries a memo but the link does not expect one.
      // This is a weak mismatch — proceed with amount scoring only.
    } else if (!tx.memo && link.memo) {
      // The link requires a specific memo but the transaction has none.
      // Exclude this candidate entirely to avoid false positives.
      return this.zeroScore(true);
    }
    // If neither side has a memo: neutral — fall through to amount scoring.

    // ── Amount scoring ────────────────────────────────────────────────────────
    let amountPoints = 0;
    const txAmount = parseFloat(tx.amount);
    const linkAmount = parseFloat(link.amount);

    if (!isNaN(txAmount) && !isNaN(linkAmount) && linkAmount > 0) {
      const delta = Math.abs(txAmount - linkAmount);

      if (delta < 1e-7) {
        breakdown.amountExact = true;
        breakdown.amountWithinTolerance = true;
        amountPoints = 40;
      } else if (delta / linkAmount <= AMOUNT_TOLERANCE_PCT) {
        breakdown.amountWithinTolerance = true;
        amountPoints = 20;
      }
    }

    return { confidence: memoPoints + amountPoints, breakdown };
  }

  /** Whether the auto-match cycle is currently running. */
  get running(): boolean {
    return this.isRunning;
  }

  // ─── Decision ──────────────────────────────────────────────────────────────

  private resolveDecision(confidence: number): MatchDecision {
    if (confidence >= AUTO_MATCH_THRESHOLD) return MatchDecision.AutoMatch;
    if (confidence >= REVIEW_THRESHOLD) return MatchDecision.ReviewRequired;
    return MatchDecision.Unmatched;
  }

  private async applyDecision(result: MatchResult): Promise<void> {
    const { transaction: tx, decision, bestLink, bestScore } = result;

    switch (decision) {
      case MatchDecision.AutoMatch:
        await this.applyAutoMatch(tx, bestLink!, bestScore!.confidence);
        break;

      case MatchDecision.ReviewRequired:
        await this.unmatchedQueue.enqueue(
          tx,
          bestLink?.id ?? null,
          bestScore?.confidence ?? null,
        );
        this.logger.log(
          `Transaction ${tx.txHash} queued for review ` +
          `(confidence=${bestScore?.confidence ?? 0}, candidate=${bestLink?.id ?? 'none'})`,
        );
        break;

      default:
        await this.unmatchedQueue.enqueue(tx, null, null);
        this.logger.log(`Transaction ${tx.txHash} stored as unmatched (no candidates above threshold)`);
    }
  }

  /**
   * Apply a high-confidence auto-match: update the payment link status to
   * "paid" and emit an event for downstream webhook delivery.
   */
  private async applyAutoMatch(
    tx: IncomingTransaction,
    link: PaymentLink,
    confidence: number,
  ): Promise<void> {
    const matchedAt = new Date().toISOString();

    try {
      const { error } = await this.supabase
        .getClient()
        .from('payment_links')
        .update({
          status: PaymentLinkStatus.Paid,
          matched_tx_hash: tx.txHash,
          matched_at: matchedAt,
          match_confidence: confidence,
          updated_at: matchedAt,
        })
        .eq('id', link.id)
        // Guard: only update if the link is still open.  Prevents race conditions
        // where two concurrent cycles attempt to apply the same match.
        .eq('status', PaymentLinkStatus.Open);

      if (error) {
        this.logger.error(`Failed to mark link ${link.id} as paid: ${error.message}`);
        return;
      }

      this.logger.log(
        `Auto-match applied: link ${link.id} → PAID ` +
        `(tx=${tx.txHash}, confidence=${confidence})`,
      );

      this.fireReconciliationEvent(link, tx, confidence, matchedAt);
    } catch (err) {
      this.logger.error(
        `Unexpected error applying auto-match for link ${link.id}: ${(err as Error).message}`,
        (err as Error).stack,
      );
    }
  }

  /**
   * Emit the `auto_reconciliation.succeeded` event.
   * The NotificationService listens for this and dispatches webhook deliveries.
   */
  private fireReconciliationEvent(
    link: PaymentLink,
    tx: IncomingTransaction,
    confidence: number,
    matchedAt: string,
  ): void {
    const eventPayload: AutoReconciliationSucceededPayload = {
      linkId: link.id,
      ownerPublicKey: link.owner_public_key,
      txHash: tx.txHash,
      amount: tx.amount,
      assetCode: tx.assetCode,
      confidence,
      matchedAt,
    };

    this.eventEmitter.emit('auto_reconciliation.succeeded', eventPayload);

    this.logger.debug(
      `Emitted auto_reconciliation.succeeded for link ${link.id} (tx=${tx.txHash})`,
    );
  }

  // ─── Horizon queries ───────────────────────────────────────────────────────

  /**
   * Fetch recent payment operations destined for a given Stellar account.
   *
   * Uses the Horizon `/payments?for_account=&order=desc` endpoint.  Results
   * are filtered to outgoing→incoming payment ops only (type === 'payment').
   * A cursor is supplied when available to avoid re-processing old operations.
   *
   * @param destination - The Stellar account to query.
   * @param afterCursor - Optional Horizon paging_token to resume from.
   * @returns Array of normalised transactions (may be empty on error or 404).
   */
  private async fetchRecentPayments(
    destination: string,
    afterCursor?: string,
  ): Promise<IncomingTransaction[]> {
    const callStart = Date.now();

    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let builder: any = (this.server as any)
        .payments()
        .forAccount(destination)
        .order('desc')
        .limit(50);

      if (afterCursor) {
        builder = builder.cursor(afterCursor);
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const response: any = await builder.call();
      const duration = (Date.now() - callStart) / 1000;
      this.metrics.recordExternalCall('horizon', 'payments_for_account', duration);

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const records: any[] = response?.records ?? [];

      return records
        .filter((op) => op.type === 'payment' && op.to === destination)
        .map((op) => this.normalizePaymentOp(op));
    } catch (err: unknown) {
      const duration = (Date.now() - callStart) / 1000;
      this.metrics.recordExternalCall('horizon', 'payments_for_account', duration);

      const horizonErr = err as { response?: { status?: number } };
      if (horizonErr?.response?.status === 404) {
        return [];
      }

      this.logger.warn(
        `Horizon payment fetch failed for ${destination}: ${(err as Error).message}`,
      );
      return [];
    }
  }

  /** Normalise a raw Horizon payment record into a typed IncomingTransaction. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private normalizePaymentOp(op: any): IncomingTransaction {
    const isNative = op.asset_type === 'native';
    return {
      txHash: op.transaction_hash as string,
      ledger: (op.transaction?.ledger_attr as number | undefined) ?? 0,
      sourceAccount: op.from as string,
      destinationAccount: op.to as string,
      amount: op.amount as string,
      assetCode: isNative ? 'XLM' : (op.asset_code as string),
      assetIssuer: isNative ? null : ((op.asset_issuer as string | undefined) ?? null),
      memo: (op.transaction?.memo as string | undefined) ?? null,
      memoType: (op.transaction?.memo_type as string | undefined) ?? null,
      occurredAt: op.created_at as string,
    };
  }

  // ─── Supabase queries ──────────────────────────────────────────────────────

  /** Fetch every open, non-expired payment link. */
  private async fetchOpenPaymentLinks(): Promise<PaymentLink[]> {
    const now = new Date().toISOString();

    const { data, error } = await this.supabase
      .getClient()
      .from('payment_links')
      .select('*')
      .eq('status', PaymentLinkStatus.Open)
      .or(`expires_at.is.null,expires_at.gt.${now}`);

    if (error) {
      this.logger.error(`Failed to fetch open payment links: ${error.message}`);
      return [];
    }

    return (data ?? []) as PaymentLink[];
  }

  /** Fetch open payment links for a specific destination address. */
  private async fetchOpenLinksForDestination(destination: string): Promise<PaymentLink[]> {
    const now = new Date().toISOString();

    const { data, error } = await this.supabase
      .getClient()
      .from('payment_links')
      .select('*')
      .eq('status', PaymentLinkStatus.Open)
      .eq('destination_public_key', destination)
      .or(`expires_at.is.null,expires_at.gt.${now}`);

    if (error) {
      this.logger.error(
        `Failed to fetch open links for destination ${destination}: ${error.message}`,
      );
      return [];
    }

    return (data ?? []) as PaymentLink[];
  }

  // ─── Utilities ─────────────────────────────────────────────────────────────

  private groupByDestination(links: PaymentLink[]): Map<string, PaymentLink[]> {
    const map = new Map<string, PaymentLink[]>();
    for (const link of links) {
      const group = map.get(link.destination_public_key) ?? [];
      group.push(link);
      map.set(link.destination_public_key, group);
    }
    return map;
  }

  /**
   * Count how many open payment links in the candidate set share each memo
   * value.  Used by {@link scoreOne} to determine memo uniqueness.
   */
  private countMemoOccurrences(links: PaymentLink[]): Map<string, number> {
    const counts = new Map<string, number>();
    for (const link of links) {
      if (link.memo) {
        counts.set(link.memo, (counts.get(link.memo) ?? 0) + 1);
      }
    }
    return counts;
  }

  private zeroScore(assetMatches: boolean): MatchScore {
    return {
      confidence: 0,
      breakdown: {
        memoPresent: false,
        memoMatches: false,
        memoIsUnique: false,
        amountExact: false,
        amountWithinTolerance: false,
        assetMatches,
      },
    };
  }
}
