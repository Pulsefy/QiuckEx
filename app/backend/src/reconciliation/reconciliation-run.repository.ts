import { Injectable, Logger } from '@nestjs/common';

import { SupabaseService } from '../supabase/supabase.service';
import {
  ReconciliationRunStatus,
  ReconciliationRunSummary,
} from './types/reconciliation.types';

/** Row shape of the `reconciliation_runs` table (snake_case). */
interface ReconciliationRunRow {
  run_id: string;
  status: ReconciliationRunStatus;
  batch_size: number | null;
  started_at: string;
  completed_at: string | null;
  duration_ms: number | null;
  escrows_processed: number;
  escrows_irreconcilable: number;
  payments_processed: number;
  payments_irreconcilable: number;
  count_discrepancy: number;
  amount_discrepancy: string;
  drift_exceeded: boolean;
  alert_severity: 'warning' | 'critical' | null;
  alert_message: string | null;
  failure_reason: string | null;
  skipped_reason: string | null;
  drift_details: unknown;
}

/** Paginated result returned by {@link ReconciliationRunRepository.listRuns}. */
export interface ReconciliationRunPage {
  items: ReconciliationRunSummary[];
  total: number;
  hasMore: boolean;
}

/**
 * ReconciliationRunRepository
 *
 * Data-access layer for the `reconciliation_runs` table (see
 * `supabase/migrations/20260830000000_create_reconciliation_runs.sql`).
 *
 * Stores a summary per scheduled/manual reconciliation run, exposes run history
 * to operators with per-run drift detail, and computes the current consecutive
 * failed/skipped streak used by the drift alerting path (BE-124).
 */
@Injectable()
export class ReconciliationRunRepository {
  private readonly logger = new Logger(ReconciliationRunRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  /**
   * Persist (or overwrite) a run summary. Idempotent on `run_id` so a retried
   * run never creates duplicate history rows.
   */
  async save(summary: ReconciliationRunSummary): Promise<void> {
    const { error } = await this.supabase
      .getClient()
      .from('reconciliation_runs')
      .upsert(this.toRow(summary), { onConflict: 'run_id' });

    if (error) {
      this.logger.error(
        `Failed to persist reconciliation run ${summary.runId}: ${error.message}`,
      );
    }
  }

  /**
   * Return a page of run history, newest first. Optionally filtered by status.
   */
  async listRuns(options: {
    limit: number;
    offset: number;
    status?: ReconciliationRunStatus;
  }): Promise<ReconciliationRunPage> {
    const effectiveLimit = Math.min(100, Math.max(1, options.limit));

    let query = this.supabase
      .getClient()
      .from('reconciliation_runs')
      .select('*', { count: 'exact' })
      .order('started_at', { ascending: false });

    if (options.status) {
      query = query.eq('status', options.status);
    }

    const { data, error, count } = await query.range(
      options.offset,
      options.offset + effectiveLimit - 1,
    );

    if (error) {
      this.logger.error(
        `Failed to list reconciliation runs: ${error.message}`,
      );
      return { items: [], total: 0, hasMore: false };
    }

    const total = count ?? 0;
    const items = (data ?? []).map((row: ReconciliationRunRow) =>
      this.toSummary(row),
    );

    return {
      items,
      total,
      hasMore: options.offset + effectiveLimit < total,
    };
  }

  /** Look up a single run summary (with its drift detail) by run id. */
  async findById(runId: string): Promise<ReconciliationRunSummary | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from('reconciliation_runs')
      .select('*')
      .eq('run_id', runId)
      .maybeSingle();

    if (error) {
      this.logger.error(
        `Failed to find reconciliation run ${runId}: ${error.message}`,
      );
      return null;
    }

    return data ? this.toSummary(data as ReconciliationRunRow) : null;
  }

  /**
   * Count how many of the most recent runs are incomplete (failed or skipped),
   * scanning newest-first until a successful/drifted run breaks the streak.
   * Used to alert when consecutive failed/skipped runs exceed a threshold.
   */
  async countConsecutiveIncompleteRuns(
    lookback = 100,
  ): Promise<number> {
    const { data, error } = await this.supabase
      .getClient()
      .from('reconciliation_runs')
      .select('status')
      .order('started_at', { ascending: false })
      .limit(Math.max(1, lookback));

    if (error) {
      this.logger.error(
        `Failed to read reconciliation run history: ${error.message}`,
      );
      return 0;
    }

    let consecutive = 0;
    for (const row of data ?? []) {
      if (row.status === 'failed' || row.status === 'skipped') {
        consecutive += 1;
      } else {
        break;
      }
    }
    return consecutive;
  }

  private toRow(summary: ReconciliationRunSummary): Record<string, unknown> {
    return {
      run_id: summary.runId,
      status: summary.status,
      batch_size: summary.batchSize ?? null,
      started_at: summary.startedAt,
      completed_at: summary.completedAt,
      duration_ms: summary.durationMs,
      escrows_processed: summary.escrowsProcessed,
      escrows_irreconcilable: summary.escrowsIrreconcilable,
      payments_processed: summary.paymentsProcessed,
      payments_irreconcilable: summary.paymentsIrreconcilable,
      count_discrepancy: summary.countDiscrepancy,
      amount_discrepancy: summary.amountDiscrepancy,
      drift_exceeded: summary.driftExceeded,
      alert_severity: summary.alertSeverity ?? null,
      alert_message: summary.alertMessage ?? null,
      failure_reason: summary.failureReason ?? null,
      skipped_reason: summary.skippedReason ?? null,
      drift_details: summary.driftDetails,
    };
  }

  private toSummary(row: ReconciliationRunRow): ReconciliationRunSummary {
    return {
      runId: row.run_id,
      status: row.status,
      batchSize: row.batch_size ?? undefined,
      startedAt: row.started_at,
      completedAt: row.completed_at,
      durationMs: row.duration_ms,
      escrowsProcessed: row.escrows_processed,
      escrowsIrreconcilable: row.escrows_irreconcilable,
      paymentsProcessed: row.payments_processed,
      paymentsIrreconcilable: row.payments_irreconcilable,
      countDiscrepancy: row.count_discrepancy,
      amountDiscrepancy: row.amount_discrepancy,
      driftExceeded: row.drift_exceeded,
      alertSeverity: row.alert_severity ?? undefined,
      alertMessage: row.alert_message ?? undefined,
      failureReason: row.failure_reason ?? undefined,
      skippedReason: row.skipped_reason ?? undefined,
      driftDetails: (row.drift_details ?? []) as ReconciliationRunSummary['driftDetails'],
    };
  }
}