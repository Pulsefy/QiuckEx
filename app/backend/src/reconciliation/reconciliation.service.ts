import { Injectable, Logger } from '@nestjs/common';
import { Horizon } from '@stellar/stellar-sdk';
import { v4 as uuidv4 } from 'uuid';

import { AppConfigService } from '../config/app-config.service';
import { SupabaseService } from '../supabase/supabase.service';
import { MetricsService } from '../metrics/metrics.service';
import { SentryService } from '../sentry/sentry.service';
import { ReconciliationRunRepository } from './reconciliation-run.repository';
import {
  EscrowDbStatus,
  EscrowRecord,
  EscrowReconciliationResult,
  OnChainState,
  PaymentDbStatus,
  PaymentRecord,
  PaymentReconciliationResult,
  ReconciliationAction,
  ReconciliationDriftDetail,
  ReconciliationReport,
  ReconciliationRunStatus,
  ReconciliationRunSummary,
} from './types/reconciliation.types';

@Injectable()
export class ReconciliationService {
  private readonly logger = new Logger(ReconciliationService.name);
  private readonly server: Horizon.Server;

  /**
   * Tracks whether the consecutive failed/skipped run alert is currently
   * firing, so it is raised once per streak instead of on every tick (BE-124).
   */
  private consecutiveFailureAlerted = false;

  /** Statuses that need to be reconciled against the chain. */
  private readonly ACTIONABLE_ESCROW_STATUSES: EscrowDbStatus[] = [
    EscrowDbStatus.Pending,
    EscrowDbStatus.Active,
  ];

  private readonly ACTIONABLE_PAYMENT_STATUSES: PaymentDbStatus[] = [
    PaymentDbStatus.Pending,
    PaymentDbStatus.Processing,
  ];

  constructor(
    private readonly config: AppConfigService,
    private readonly supabase: SupabaseService,
    private readonly metrics: MetricsService,
    private readonly runRepository: ReconciliationRunRepository,
    private readonly sentry: SentryService,
  ) {
    const horizonUrl =
      config.network === 'mainnet'
        ? 'https://horizon.stellar.org'
        : 'https://horizon-testnet.stellar.org';

    this.server = new Horizon.Server(horizonUrl);
    this.logger.log(
      `ReconciliationService initialized against ${config.network} (${horizonUrl})`,
    );
  }

  // ---------------------------------------------------------------------------
  // Public entry point
  // ---------------------------------------------------------------------------

  async runReconciliation(batchSize: number): Promise<ReconciliationReport> {
    const runId = uuidv4();
    const startedAt = new Date().toISOString();
    const startMs = Date.now();

    this.logger.log(`[${runId}] Reconciliation run started (batchSize=${batchSize})`);

    const [escrowResults, paymentResults] = await Promise.all([
      this.reconcileEscrows(runId, batchSize),
      this.reconcilePayments(runId, batchSize),
    ]);

    const completedAt = new Date().toISOString();
    const durationMs = Date.now() - startMs;

    const report: ReconciliationReport = {
      runId,
      startedAt,
      completedAt,
      durationMs,
      escrows: this.summarise(escrowResults),
      payments: this.summarise(paymentResults),
    };

    // Add totals comparison for payments
    report.totalsComparison = await this.comparePaymentTotals(runId);

    // Classify the run (clean vs drift) and raise an alert when configured
    // drift thresholds are exceeded (BE-124).
    const classification = this.classifyRun(report);
    report.alert = classification.alert;
    this.metrics.setReconciliationDriftActive(
      classification.status === 'drift' ? 1 : 0,
    );

    // Persist a summary for this run. Persistence is best-effort — a failed
    // history write must never take down reconciliation itself.
    await this.persistRunSummary(report, classification, batchSize);

    // A completed (even drift-flagged) run breaks any consecutive-failure streak.
    await this.evaluateConsecutiveFailures();

    this.logReport(report);
    return report;
  }

  // ---------------------------------------------------------------------------
  // Escrow reconciliation
  // ---------------------------------------------------------------------------

  private async reconcileEscrows(
    runId: string,
    batchSize: number,
  ): Promise<EscrowReconciliationResult[]> {
    const records = await this.supabase.fetchPendingEscrows(
      this.ACTIONABLE_ESCROW_STATUSES,
      batchSize,
    );

    this.logger.log(
      `[${runId}] Found ${records.length} escrow(s) to reconcile`,
    );

    const results: EscrowReconciliationResult[] = [];

    for (const record of records) {
      const result = await this.reconcileEscrow(runId, record);
      results.push(result);
    }

    return results;
  }

  private async reconcileEscrow(
    runId: string,
    record: EscrowRecord,
  ): Promise<EscrowReconciliationResult> {
    const base: Omit<EscrowReconciliationResult, 'onChainState' | 'resolvedDbStatus' | 'action' | 'irreconcilable' | 'irreconcilableReason'> = {
      id: record.id,
      contractAddress: record.contract_address,
      previousDbStatus: record.status,
    };

    let onChainState: OnChainState;
    try {
      onChainState = await this.resolveEscrowOnChainState(record);
    } catch (err) {
      this.logger.warn(
        `[${runId}] Skipping escrow ${record.id}: Horizon unavailable — ${(err as Error).message}`,
      );
      return {
        ...base,
        onChainState: OnChainState.Unknown,
        resolvedDbStatus: null,
        action: ReconciliationAction.Skipped,
        irreconcilable: false,
      };
    }

    return this.applyEscrowTransition(runId, record, onChainState, base);
  }

  /**
   * Resolves the authoritative on-chain state for an escrow account.
   *
   * Strategy:
   *  1. Load the Stellar account (contract_address).
   *  2. If the account does not exist → NonExistent.
   *  3. If the account exists, check whether the XLM balance is zero (merged indicator).
   *  4. Cross-check the DB `expires_at` field against wall-clock time.
   */
  private async resolveEscrowOnChainState(record: EscrowRecord): Promise<OnChainState> {
    const startTime = Date.now();
    try {
      const account = await this.server.loadAccount(record.contract_address);
      const duration = (Date.now() - startTime) / 1000;
      this.metrics.recordExternalCall('horizon', 'loadAccount', duration);

      // Check balance — a merged / swept account will have no native balance entry
      const nativeLine = (account.balances as Horizon.HorizonApi.BalanceLine[]).find(
        (b) => b.asset_type === 'native',
      );

      const nativeBalance = nativeLine ? parseFloat(nativeLine.balance) : 0;

      if (nativeBalance === 0) {
        // Account merged or all funds removed → treat as claimed
        return OnChainState.Claimed;
      }

      // Check expiry using DB field (Stellar doesn't natively expose time-bounds per-account)
      if (record.expires_at) {
        const expiresAt = new Date(record.expires_at).getTime();
        if (Date.now() > expiresAt) {
          return OnChainState.Expired;
        }
      }

      return OnChainState.Active;
    } catch (err: unknown) {
      const duration = (Date.now() - startTime) / 1000;
      this.metrics.recordExternalCall('horizon', 'loadAccount', duration);
      const errorType = err instanceof Error ? err.constructor.name : 'UnknownError';
      this.metrics.recordError('horizon', errorType);

      const horizonErr = err as { response?: { status?: number } };
      if (horizonErr?.response?.status === 404) {
        return OnChainState.NonExistent;
      }
      throw err; // Let the caller handle unexpected errors
    }
  }

  private async applyEscrowTransition(
    runId: string,
    record: EscrowRecord,
    onChainState: OnChainState,
    base: Omit<EscrowReconciliationResult, 'onChainState' | 'resolvedDbStatus' | 'action' | 'irreconcilable' | 'irreconcilableReason'>,
  ): Promise<EscrowReconciliationResult> {
    const { id, status: dbStatus } = record;

    // ── Transition table ─────────────────────────────────────────────────────
    // DB: pending | active  → chain says Claimed  → DB: claimed
    // DB: pending | active  → chain says Expired  → DB: expired
    // DB: pending | active  → chain says Active   → DB: no change (consistent)
    // DB: pending | active  → chain says NonExistent → irreconcilable (alert)
    // ─────────────────────────────────────────────────────────────────────────

    if (onChainState === OnChainState.Claimed) {
      await this.supabase.updateEscrowStatus(id, EscrowDbStatus.Claimed);
      this.logger.log(
        `[${runId}] Escrow ${id}: DB was '${dbStatus}' but chain is Claimed → updated to 'claimed'`,
      );
      return { ...base, onChainState, resolvedDbStatus: EscrowDbStatus.Claimed, action: ReconciliationAction.Updated, irreconcilable: false };
    }

    if (onChainState === OnChainState.Expired) {
      await this.supabase.updateEscrowStatus(id, EscrowDbStatus.Expired);
      this.logger.log(
        `[${runId}] Escrow ${id}: DB was '${dbStatus}' but chain indicates Expired → updated to 'expired'`,
      );
      return { ...base, onChainState, resolvedDbStatus: EscrowDbStatus.Expired, action: ReconciliationAction.Updated, irreconcilable: false };
    }

    if (onChainState === OnChainState.NonExistent) {
      const reason = `DB status is '${dbStatus}' but escrow account does not exist on-chain`;
      await this.supabase.flagIrreconcilableEscrow(id, reason);
      this.logger.error(
        `[${runId}] IRRECONCILABLE escrow ${id} (${record.contract_address}): ${reason}`,
      );
      return { ...base, onChainState, resolvedDbStatus: null, action: ReconciliationAction.Flagged, irreconcilable: true, irreconcilableReason: reason };
    }

    // Active on-chain and active in DB → consistent
    return { ...base, onChainState, resolvedDbStatus: dbStatus, action: ReconciliationAction.NoOp, irreconcilable: false };
  }

  // ---------------------------------------------------------------------------
  // Payment reconciliation
  // ---------------------------------------------------------------------------

  private async reconcilePayments(
    runId: string,
    batchSize: number,
  ): Promise<PaymentReconciliationResult[]> {
    const records = await this.supabase.fetchPendingPayments(
      this.ACTIONABLE_PAYMENT_STATUSES,
      batchSize,
    );

    this.logger.log(
      `[${runId}] Found ${records.length} payment(s) to reconcile`,
    );

    const results: PaymentReconciliationResult[] = [];

    for (const record of records) {
      const result = await this.reconcilePayment(runId, record);
      results.push(result);
    }

    return results;
  }

  private async reconcilePayment(
    runId: string,
    record: PaymentRecord,
  ): Promise<PaymentReconciliationResult> {
    const base: Omit<PaymentReconciliationResult, 'onChainState' | 'resolvedDbStatus' | 'action' | 'irreconcilable' | 'irreconcilableReason'> = {
      id: record.id,
      txHash: record.stellar_tx_hash,
      previousDbStatus: record.status,
    };

    let onChainState: OnChainState;
    try {
      onChainState = await this.resolvePaymentOnChainState(record.stellar_tx_hash);
    } catch (err) {
      this.logger.warn(
        `[${runId}] Skipping payment ${record.id}: Horizon unavailable — ${(err as Error).message}`,
      );
      return {
        ...base,
        onChainState: OnChainState.Unknown,
        resolvedDbStatus: null,
        action: ReconciliationAction.Skipped,
        irreconcilable: false,
      };
    }

    return this.applyPaymentTransition(runId, record, onChainState, base);
  }

  /**
   * Checks whether a transaction hash is confirmed on-chain via Horizon.
   */
  private async resolvePaymentOnChainState(txHash: string): Promise<OnChainState> {
    const startTime = Date.now();
    try {
      const tx = await this.server.transactions().transaction(txHash).call();
      const duration = (Date.now() - startTime) / 1000;
      this.metrics.recordExternalCall('horizon', 'getTransaction', duration);
      return tx.successful ? OnChainState.Confirmed : OnChainState.NonExistent;
    } catch (err: unknown) {
      const duration = (Date.now() - startTime) / 1000;
      this.metrics.recordExternalCall('horizon', 'getTransaction', duration);
      const errorType = err instanceof Error ? err.constructor.name : 'UnknownError';
      this.metrics.recordError('horizon', errorType);

      const horizonErr = err as { response?: { status?: number } };
      if (horizonErr?.response?.status === 404) {
        return OnChainState.NonExistent;
      }
      throw err;
    }
  }

  private async applyPaymentTransition(
    runId: string,
    record: PaymentRecord,
    onChainState: OnChainState,
    base: Omit<PaymentReconciliationResult, 'onChainState' | 'resolvedDbStatus' | 'action' | 'irreconcilable' | 'irreconcilableReason'>,
  ): Promise<PaymentReconciliationResult> {
    const { id, status: dbStatus } = record;

    // ── Transition table ─────────────────────────────────────────────────────
    // DB: pending | processing  → chain Confirmed     → DB: paid
    // DB: pending | processing  → chain NonExistent   → DB: failed  (irreconcilable if DB was 'paid')
    // DB: paid                  → chain NonExistent   → irreconcilable
    // ─────────────────────────────────────────────────────────────────────────

    if (onChainState === OnChainState.Confirmed) {
      if (dbStatus === PaymentDbStatus.Paid) {
        // Already consistent
        return { ...base, onChainState, resolvedDbStatus: PaymentDbStatus.Paid, action: ReconciliationAction.NoOp, irreconcilable: false };
      }
      await this.supabase.updatePaymentStatus(id, PaymentDbStatus.Paid);
      this.logger.log(
        `[${runId}] Payment ${id}: DB was '${dbStatus}' but chain confirms tx → updated to 'paid'`,
      );
      return { ...base, onChainState, resolvedDbStatus: PaymentDbStatus.Paid, action: ReconciliationAction.Updated, irreconcilable: false };
    }

    if (onChainState === OnChainState.NonExistent) {
      if (dbStatus === PaymentDbStatus.Paid) {
        const reason = `DB status is 'paid' but transaction ${record.stellar_tx_hash} not found on-chain`;
        await this.supabase.flagIrreconcilablePayment(id, reason);
        this.logger.error(
          `[${runId}] IRRECONCILABLE payment ${id}: ${reason}`,
        );
        return { ...base, onChainState, resolvedDbStatus: null, action: ReconciliationAction.Flagged, irreconcilable: true, irreconcilableReason: reason };
      }

      // pending/processing with no on-chain record — mark failed
      await this.supabase.updatePaymentStatus(id, PaymentDbStatus.Failed);
      this.logger.warn(
        `[${runId}] Payment ${id}: DB was '${dbStatus}' but tx not found on-chain → updated to 'failed'`,
      );
      return { ...base, onChainState, resolvedDbStatus: PaymentDbStatus.Failed, action: ReconciliationAction.Updated, irreconcilable: false };
    }

    // Unknown / skip
    return { ...base, onChainState, resolvedDbStatus: dbStatus, action: ReconciliationAction.NoOp, irreconcilable: false };
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private summarise<T extends { action: ReconciliationAction; irreconcilable: boolean }>(
    results: T[],
  ) {
    return {
      processed: results.length,
      updated: results.filter((r) => r.action === ReconciliationAction.Updated).length,
      noOp: results.filter((r) => r.action === ReconciliationAction.NoOp).length,
      skipped: results.filter((r) => r.action === ReconciliationAction.Skipped).length,
      irreconcilable: results.filter((r) => r.irreconcilable).length,
      results,
    };
  }

  /**
   * Compare expected vs observed payment totals to detect discrepancies.
   * Expected: Count and sum of payments in 'paid' status in DB
   * Observed: Count and sum of confirmed transactions on-chain
   */
  private async comparePaymentTotals(runId: string) {
    try {
      // Get expected totals from database (paid payments)
      const dbPayments = await this.supabase.fetchPaidPayments();
      const expectedCount = dbPayments.length;
      const expectedTotalAmount = dbPayments.reduce(
        (sum, p) => sum + BigInt(p.amount),
        0n,
      ).toString();

      // Get observed totals from on-chain (this is a simplified version)
      // In production, you would query Horizon for all transactions in a time range
      const observedCount = expectedCount; // Placeholder - would be from Horizon
      const observedTotalAmount = expectedTotalAmount; // Placeholder - would be from Horizon

      const countDiscrepancy = Math.abs(expectedCount - observedCount);
      const amountDiscrepancy = (
        BigInt(expectedTotalAmount) - BigInt(observedTotalAmount)
      ).toString();

      // Drift thresholds are configurable (BE-124): alert when the count
      // discrepancy exceeds the configured count threshold or the absolute
      // amount discrepancy exceeds the configured stroop threshold.
      const countThreshold = this.config.reconciliationDriftCountThreshold;
      const amountThreshold = BigInt(
        this.config.reconciliationDriftAmountThresholdStroops,
      );
      const absAmountDiscrepancy = amountDiscrepancy.startsWith('-')
        ? -BigInt(amountDiscrepancy)
        : BigInt(amountDiscrepancy);

      const exceedsThreshold =
        countDiscrepancy > countThreshold ||
        absAmountDiscrepancy > amountThreshold;

      this.logger.log(
        `[${runId}] Payment totals comparison: expected=${expectedCount}/${expectedTotalAmount}, observed=${observedCount}/${observedTotalAmount}, exceedsThreshold=${exceedsThreshold}`,
      );

      return {
        payments: {
          expectedCount,
          observedCount,
          countDiscrepancy,
          expectedTotalAmount,
          observedTotalAmount,
          amountDiscrepancy,
          exceedsThreshold,
        },
      };
    } catch (error) {
      this.logger.warn(
        `[${runId}] Failed to compare payment totals: ${error instanceof Error ? error.message : String(error)}`,
      );
      return undefined;
    }
  }

  /**
   * Classify a finished run as clean or drifting and, when drift exceeds the
   * configured thresholds, raise an alert through the monitoring path
   * (metrics + Sentry + structured logs).
   */
  private classifyRun(
    report: ReconciliationReport,
  ): { status: Extract<ReconciliationRunStatus, 'success' | 'drift'>; alert?: ReconciliationReport['alert'] } {
    if (!report.totalsComparison?.payments.exceedsThreshold) {
      return { status: 'success' };
    }

    const { countDiscrepancy, amountDiscrepancy } = report.totalsComparison.payments;

    const amountThreshold = BigInt(
      this.config.reconciliationDriftAmountThresholdStroops,
    );
    const absAmountDiscrepancy = amountDiscrepancy.startsWith('-')
      ? -BigInt(amountDiscrepancy)
      : BigInt(amountDiscrepancy);
    const amountExceeds = absAmountDiscrepancy > amountThreshold;

    // Critical when money is off (amount drift) or the count discrepancy is
    // more than double the configured count threshold; otherwise a warning.
    const isCritical =
      amountExceeds || countDiscrepancy > this.config.reconciliationDriftCountThreshold * 2;

    const alert: ReconciliationReport['alert'] = {
      severity: isCritical ? 'critical' : 'warning',
      message: isCritical
        ? 'Critical payment discrepancy detected'
        : 'Payment discrepancy detected',
      details: `Count discrepancy: ${countDiscrepancy}, Amount discrepancy: ${amountDiscrepancy}`,
    };

    this.raiseDriftAlert(report.runId, alert);
    return { status: 'drift', alert };
  }

  private raiseDriftAlert(runId: string, alert: ReconciliationReport['alert']): void {
    if (!alert) return;

    this.logger.error(`[${runId}] ${alert.message}: ${alert.details}`);

    this.metrics.recordError(
      'reconciliation',
      alert.severity === 'critical' ? 'critical_drift' : 'warning_drift',
    );

    this.sentry.captureMessage(
      `[reconciliation] ${alert.message}`,
      alert.severity === 'critical' ? 'fatal' : 'warning',
      {
        runId,
        details: alert.details,
        severity: alert.severity,
      },
    );
  }

  // ---------------------------------------------------------------------------
  // BE-124: Run history persistence + consecutive failure alerting
  // ---------------------------------------------------------------------------

  private async persistRunSummary(
    report: ReconciliationReport,
    classification: { status: ReconciliationRunStatus; alert?: ReconciliationReport['alert'] },
    batchSize: number,
  ): Promise<void> {
    const totals = report.totalsComparison?.payments;

    const summary: ReconciliationRunSummary = {
      runId: report.runId,
      status: classification.status,
      batchSize,
      startedAt: report.startedAt,
      completedAt: report.completedAt,
      durationMs: report.durationMs,
      escrowsProcessed: report.escrows.processed,
      escrowsIrreconcilable: report.escrows.irreconcilable,
      paymentsProcessed: report.payments.processed,
      paymentsIrreconcilable: report.payments.irreconcilable,
      countDiscrepancy: totals?.countDiscrepancy ?? 0,
      amountDiscrepancy: totals?.amountDiscrepancy ?? '0',
      driftExceeded: totals?.exceedsThreshold ?? false,
      alertSeverity: classification.alert?.severity,
      alertMessage: classification.alert?.message,
      driftDetails: this.buildDriftDetails(report),
    };

    try {
      await this.runRepository.save(summary);
    } catch (err) {
      this.logger.warn(
        `[${report.runId}] Failed to persist run summary: ${(err as Error).message}`,
      );
    }
  }

  private buildDriftDetails(report: ReconciliationReport): ReconciliationDriftDetail[] {
    const details: ReconciliationDriftDetail[] = [];

    for (const r of report.escrows.results) {
      if (r.action === ReconciliationAction.NoOp) continue;
      details.push({
        entityType: 'escrow',
        id: r.id,
        onChainState: r.onChainState,
        previousDbStatus: r.previousDbStatus,
        resolvedDbStatus: r.resolvedDbStatus,
        action: r.action,
        irreconcilableReason: r.irreconcilableReason,
      });
    }

    for (const r of report.payments.results) {
      if (r.action === ReconciliationAction.NoOp) continue;
      details.push({
        entityType: 'payment',
        id: r.id,
        onChainState: r.onChainState,
        previousDbStatus: r.previousDbStatus,
        resolvedDbStatus: r.resolvedDbStatus,
        action: r.action,
        irreconcilableReason: r.irreconcilableReason,
      });
    }

    return details;
  }

  /**
   * Persist a failed run (e.g. a job execution failure, enqueue failure, or
   * manual-trigger exception) so the consecutive-failure alerting path can
   * see it. Best-effort — never throws back to the caller.
   */
  async recordFailedRun(
    failureReason: string,
    context?: { batchSize?: number },
  ): Promise<void> {
    const runId = uuidv4();
    this.logger.error(`[${runId}] Reconciliation run failed: ${failureReason}`);
    this.metrics.recordError('reconciliation', 'run_failed');

    const summary: ReconciliationRunSummary = {
      runId,
      status: 'failed',
      batchSize: context?.batchSize,
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: null,
      escrowsProcessed: 0,
      escrowsIrreconcilable: 0,
      paymentsProcessed: 0,
      paymentsIrreconcilable: 0,
      countDiscrepancy: 0,
      amountDiscrepancy: '0',
      driftExceeded: false,
      failureReason,
      driftDetails: [],
    };

    try {
      await this.runRepository.save(summary);
    } catch (err) {
      this.logger.warn(
        `[${runId}] Failed to persist failed run summary: ${(err as Error).message}`,
      );
    }

    await this.evaluateConsecutiveFailures();
  }

  /**
   * Persist a skipped run (e.g. a cron tick skipped because a previous run was
   * still in progress) so the consecutive-failure alerting path can see it.
   */
  async recordSkippedRun(
    skippedReason: string,
    context?: { batchSize?: number },
  ): Promise<void> {
    const runId = uuidv4();
    this.logger.warn(`[${runId}] Reconciliation run skipped: ${skippedReason}`);
    this.metrics.recordError('reconciliation', 'run_skipped');

    const summary: ReconciliationRunSummary = {
      runId,
      status: 'skipped',
      batchSize: context?.batchSize,
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: null,
      escrowsProcessed: 0,
      escrowsIrreconcilable: 0,
      paymentsProcessed: 0,
      paymentsIrreconcilable: 0,
      countDiscrepancy: 0,
      amountDiscrepancy: '0',
      driftExceeded: false,
      skippedReason,
      driftDetails: [],
    };

    try {
      await this.runRepository.save(summary);
    } catch (err) {
      this.logger.warn(
        `[${runId}] Failed to persist skipped run summary: ${(err as Error).message}`,
      );
    }

    await this.evaluateConsecutiveFailures();
  }

  /**
   * Evaluate the current consecutive failed/skipped run streak and raise an
   * alert when it reaches the configured threshold. The alert fires once per
   * new streak (not on every tick) so operators are not spammed.
   */
  async evaluateConsecutiveFailures(): Promise<void> {
    let consecutive: number;
    try {
      consecutive = await this.runRepository.countConsecutiveIncompleteRuns();
    } catch (err) {
      this.logger.warn(
        `Unable to read reconciliation run history: ${(err as Error).message}`,
      );
      return;
    }

    this.metrics.setReconciliationConsecutiveFailures(consecutive);

    const threshold = this.config.reconciliationConsecutiveFailureAlertThreshold;

    if (consecutive >= threshold && !this.consecutiveFailureAlerted) {
      this.consecutiveFailureAlerted = true;
      const message =
        `Reconciliation has ${consecutive} consecutive failed/skipped run(s) ` +
        `(threshold: ${threshold})`;

      this.logger.error(message);
      this.metrics.recordError('reconciliation', 'consecutive_failures');
      this.sentry.captureMessage(
        `[reconciliation] ${message}`,
        'warning',
        { consecutiveFailures: consecutive, threshold },
      );
    } else if (consecutive < threshold) {
      this.consecutiveFailureAlerted = false;
    }
  }

  private logReport(report: ReconciliationReport): void {
    const { runId, durationMs, escrows, payments } = report;

    this.logger.log(
      `[${runId}] Run complete in ${durationMs}ms | ` +
      `Escrows — processed:${escrows.processed} updated:${escrows.updated} ` +
      `noOp:${escrows.noOp} skipped:${escrows.skipped} irreconcilable:${escrows.irreconcilable} | ` +
      `Payments — processed:${payments.processed} updated:${payments.updated} ` +
      `noOp:${payments.noOp} skipped:${payments.skipped} irreconcilable:${payments.irreconcilable}`,
    );

    // Warn loudly for any irreconcilable records
    const allIrreconcilable = [
      ...escrows.results.filter((r) => r.irreconcilable),
      ...payments.results.filter((r) => r.irreconcilable),
    ];

    if (allIrreconcilable.length > 0) {
      this.logger.error(
        `[${runId}] ⚠  ${allIrreconcilable.length} irreconcilable record(s) flagged for manual review`,
      );
      allIrreconcilable.forEach((r) => {
        this.logger.error(
          `  • ${'contractAddress' in r ? `escrow ${r.id}` : `payment ${r.id}`}: ${(r as { irreconcilableReason?: string }).irreconcilableReason}`,
        );
      });
    }
  }
}
