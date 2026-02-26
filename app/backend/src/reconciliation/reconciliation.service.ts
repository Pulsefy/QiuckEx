import { Injectable, Logger } from '@nestjs/common';
import { Horizon } from 'stellar-sdk';
import { v4 as uuidv4 } from 'uuid';

import { AppConfigService } from '../config/app-config.service';
import { SupabaseService } from '../supabase/supabase.service';
import {
  EscrowDbStatus,
  EscrowRecord,
  EscrowReconciliationResult,
  OnChainState,
  PaymentDbStatus,
  PaymentRecord,
  PaymentReconciliationResult,
  ReconciliationAction,
  ReconciliationReport,
} from './types/reconciliation.types';

@Injectable()
export class ReconciliationService {
  private readonly logger = new Logger(ReconciliationService.name);
  private readonly server: Horizon.Server;

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
    try {
      const account = await this.server.loadAccount(record.contract_address);

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
    try {
      const tx = await this.server.transactions().transaction(txHash).call();
      return tx.successful ? OnChainState.Confirmed : OnChainState.NonExistent;
    } catch (err: unknown) {
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
