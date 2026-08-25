/**
 * SEP-24 Polling Service
 *
 * Core logic for following anchor transaction status on all in-flight SEP-24
 * ramp transactions.  For each transaction the service:
 *
 *   1. Calls the anchor's GET /sep24/transaction endpoint.
 *   2. Persists the updated status (and stellar_tx_hash when available).
 *   3. Emits user-facing notifications for terminal states.
 *   4. Hands completed on-chain deposits/withdrawals to the reconciliation
 *      module for matching against the Stellar payment record.
 *   5. Detects stuck transactions past a configurable threshold and flags them
 *      for operator review.
 */

import { Injectable, Logger, Inject, Optional } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Horizon } from '@stellar/stellar-sdk';

import { Sep24TransactionRepository } from './sep24-transaction.repository';
import { AnchorClientService } from './anchor-client.service';
import { sep24Config } from '../config/sep24.config';
import {
  Sep24AnchorStatus,
  Sep24InternalStatus,
  Sep24PollResult,
  Sep24TransactionRecord,
  TERMINAL_ANCHOR_STATUSES,
} from './types/sep24.types';
import { AppConfigService } from '../config/app-config.service';
import { MetricsService } from '../metrics/metrics.service';
import { HORIZON_BASE_URLS } from '../config/stellar.config';
import {
  Sep24TransactionTerminalEvent,
  Sep24TransactionStuckEvent,
  NotificationEvent,
} from '../events/notification.events';
import { ReconciliationService } from '../reconciliation/reconciliation.service';

@Injectable()
export class Sep24PollingService {
  private readonly logger = new Logger(Sep24PollingService.name);
  private readonly horizonServer: Horizon.Server;

  constructor(
    private readonly repository: Sep24TransactionRepository,
    private readonly anchorClient: AnchorClientService,
    private readonly appConfig: AppConfigService,
    private readonly metrics: MetricsService,
    private readonly eventEmitter: EventEmitter2,
    @Inject(sep24Config.KEY)
    private readonly config: ConfigType<typeof sep24Config>,
    @Optional()
    private readonly reconciliationService?: ReconciliationService,
  ) {
    const horizonUrl = HORIZON_BASE_URLS[appConfig.network];
    this.horizonServer = new Horizon.Server(horizonUrl);
    this.logger.log(
      `Sep24PollingService initialised (network: ${appConfig.network}, ` +
      `stuckThresholdMs: ${config.stuckThresholdMs}, batchSize: ${config.batchSize})`,
    );
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * Execute a full poll cycle.
   *
   * Fetches a batch of in-flight transactions, polls each anchor, persists the
   * result, and triggers side-effects (events, reconciliation, stuck flagging).
   *
   * This method is self-contained and idempotent — safe to call from a cron
   * tick, a job handler, or an admin endpoint.
   *
   * @returns A summary of the cycle results.
   */
  async runPollCycle(): Promise<{
    processed: number;
    updated: number;
    terminal: number;
    stuck: number;
    failed: number;
  }> {
    let processed = 0;
    let updated = 0;
    let terminal = 0;
    let stuck = 0;
    let failed = 0;

    // ── Step 1: flag any newly-stuck transactions ────────────────────────────
    const stuckRecords = await this.repository.findStuck(
      this.config.stuckThresholdMs,
      this.config.batchSize,
    );

    for (const record of stuckRecords) {
      const reason =
        `Transaction has been in-flight for more than ` +
        `${this.config.stuckThresholdMs / 1000}s without reaching a terminal state`;

      await this.repository.flagAsStuck(record.id, reason);
      this.emitStuck(record, reason);
      stuck++;

      this.logger.warn(
        `SEP-24 transaction ${record.id} (anchor=${record.anchor_transaction_id}) ` +
        `flagged as stuck: ${reason}`,
      );
    }

    // ── Step 2: poll in-flight transactions ──────────────────────────────────
    const inFlight = await this.repository.findInFlight(
      this.config.batchSize,
      this.config.maxPollFailures,
    );

    if (inFlight.length === 0 && stuckRecords.length === 0) {
      this.logger.debug('SEP-24 poll cycle: no in-flight transactions to process');
      return { processed, updated, terminal, stuck, failed };
    }

    this.logger.log(
      `SEP-24 poll cycle: ${inFlight.length} in-flight, ${stuckRecords.length} newly stuck`,
    );

    for (const record of inFlight) {
      processed++;

      try {
        const result = await this.pollOne(record);

        if (result.terminal) terminal++;
        if (result.stuck) stuck++;
        if (result.errorMessage) {
          failed++;
        } else {
          updated++;
        }
      } catch (err) {
        failed++;
        this.logger.error(
          `Unexpected error polling SEP-24 transaction ${record.id}: ` +
          `${(err as Error).message}`,
          (err as Error).stack,
        );
      }
    }

    this.logger.log(
      `SEP-24 poll cycle complete: processed=${processed} updated=${updated} ` +
      `terminal=${terminal} stuck=${stuck} failed=${failed}`,
    );

    return { processed, updated, terminal, stuck, failed };
  }

  // ─── Core per-transaction polling ──────────────────────────────────────────

  /**
   * Poll the anchor for a single transaction and apply all side-effects.
   *
   * Exposed as public so admin endpoints can trigger on-demand polling.
   */
  async pollOne(record: Sep24TransactionRecord): Promise<Sep24PollResult> {
    const pollResult = await this.anchorClient.pollTransaction({
      anchorDomain: record.anchor_domain,
      transactionId: record.anchor_transaction_id,
    });

    // ── Poll failure path ────────────────────────────────────────────────────
    if (!pollResult.success || !pollResult.data) {
      const reason = pollResult.error ?? 'Unknown anchor error';
      await this.repository.incrementPollFailures(record.id, reason);

      this.logger.warn(
        `SEP-24 poll failed for ${record.id} (anchor=${record.anchor_transaction_id}): ${reason}`,
      );

      return {
        transactionId: record.id,
        anchorTransactionId: record.anchor_transaction_id,
        previousInternalStatus: record.status,
        anchorStatus: Sep24AnchorStatus.Unknown,
        newInternalStatus: record.status,
        stellarTxHash: record.stellar_tx_hash,
        terminal: false,
        stuck: false,
        reconciled: false,
        errorMessage: reason,
      };
    }

    // ── Successful poll — derive new status ──────────────────────────────────
    const anchorTx = pollResult.data.transaction;
    const anchorStatus = Sep24TransactionRepository.parseAnchorStatus(anchorTx.status);
    const newInternalStatus = Sep24TransactionRepository.toInternalStatus(anchorStatus);
    const stellarTxHash = anchorTx.stellar_transaction_id ?? record.stellar_tx_hash;

    const isTerminal = TERMINAL_ANCHOR_STATUSES.has(anchorStatus);
    const statusChanged = newInternalStatus !== record.status;

    // Only write to DB when something actually changed
    if (statusChanged || stellarTxHash !== record.stellar_tx_hash) {
      const terminalAt = isTerminal ? new Date().toISOString() : undefined;
      const failureReason = isTerminal && (
        anchorStatus === Sep24AnchorStatus.Error ||
        anchorStatus === Sep24AnchorStatus.AnchorError
      )
        ? (anchorTx.message ?? `Anchor status: ${anchorStatus}`)
        : undefined;

      await this.repository.updateStatus(
        record.id,
        newInternalStatus,
        anchorTx.status,
        stellarTxHash,
        { failureReason, terminalAt },
      );

      this.logger.log(
        `SEP-24 transaction ${record.id}: ` +
        `${record.status} → ${newInternalStatus} ` +
        `(anchor: ${anchorTx.status}, stellar_tx_hash: ${stellarTxHash ?? 'none'})`,
      );
    }

    // ── Terminal side-effects ────────────────────────────────────────────────
    let reconciled = false;
    if (isTerminal && statusChanged) {
      this.emitTerminal(record, anchorStatus, newInternalStatus, stellarTxHash);

      // For completed deposits/withdrawals, try to reconcile against on-chain
      if (
        newInternalStatus === Sep24InternalStatus.Completed &&
        stellarTxHash
      ) {
        reconciled = await this.reconcileOnChain(record, stellarTxHash);
      }
    }

    return {
      transactionId: record.id,
      anchorTransactionId: record.anchor_transaction_id,
      previousInternalStatus: record.status,
      anchorStatus,
      newInternalStatus,
      stellarTxHash: stellarTxHash ?? null,
      terminal: isTerminal,
      stuck: false,
      reconciled,
      errorMessage: null,
    };
  }

  // ─── On-chain reconciliation ─────────────────────────────────────────────

  /**
   * Verify the completed Stellar transaction exists on-chain and surface the
   * result to the reconciliation module.
   *
   * Returns true if the transaction was successfully verified on-chain.
   */
  private async reconcileOnChain(
    record: Sep24TransactionRecord,
    stellarTxHash: string,
  ): Promise<boolean> {
    const startMs = Date.now();

    try {
      // Confirm the transaction exists on Horizon
      const tx = await this.horizonServer
        .transactions()
        .transaction(stellarTxHash)
        .call();

      const durationSec = (Date.now() - startMs) / 1000;
      this.metrics.recordExternalCall('horizon', 'sep24_tx_verify', durationSec);

      if (!tx.successful) {
        this.logger.warn(
          `SEP-24 transaction ${record.id}: Stellar tx ${stellarTxHash} ` +
          `found on-chain but unsuccessful`,
        );
        return false;
      }

      // Mark as reconciled in our DB
      await this.repository.markReconciled(record.id);

      this.logger.log(
        `SEP-24 transaction ${record.id} reconciled ` +
        `(stellar_tx_hash=${stellarTxHash}, type=${record.type})`,
      );

      // Notify the reconciliation service if available so it can cross-check
      // against payment_records / unmatched_transactions tables
      if (this.reconciliationService) {
        try {
          await this.reconciliationService.runReconciliation(
            1, // Single-record batch — only the record we just completed
          );
        } catch (reconcileErr) {
          // Non-fatal: the next scheduled reconciliation run will pick this up
          this.logger.warn(
            `Triggered reconciliation after SEP-24 completion failed: ` +
            `${(reconcileErr as Error).message}`,
          );
        }
      }

      // Emit event for downstream consumers (webhooks, notifications)
      this.eventEmitter.emit(NotificationEvent.Sep24TransactionReconciled, {
        transactionId: record.id,
        anchorTransactionId: record.anchor_transaction_id,
        anchorDomain: record.anchor_domain,
        type: record.type,
        stellarTxHash,
        amount: record.amount,
        assetCode: record.asset_code,
        userAccount: record.user_account,
        reconciledAt: new Date().toISOString(),
      });

      return true;
    } catch (err: unknown) {
      const durationSec = (Date.now() - startMs) / 1000;
      this.metrics.recordExternalCall('horizon', 'sep24_tx_verify', durationSec);

      const horizonErr = err as { response?: { status?: number } };
      if (horizonErr?.response?.status === 404) {
        this.logger.warn(
          `SEP-24 transaction ${record.id}: Stellar tx ${stellarTxHash} ` +
          `not found on Horizon — may be propagation delay`,
        );
      } else {
        this.logger.error(
          `SEP-24 reconciliation check failed for ${record.id}: ` +
          `${(err as Error).message}`,
        );
      }

      return false;
    }
  }

  // ─── Event helpers ───────────────────────────────────────────────────────

  private emitTerminal(
    record: Sep24TransactionRecord,
    anchorStatus: Sep24AnchorStatus,
    internalStatus: Sep24InternalStatus,
    stellarTxHash: string | null | undefined,
  ): void {
    const event = new Sep24TransactionTerminalEvent(
      record.id,
      record.anchor_transaction_id,
      record.anchor_domain,
      record.type,
      anchorStatus,
      internalStatus,
      stellarTxHash ?? null,
      record.amount,
      record.asset_code,
      record.user_account,
    );

    this.eventEmitter.emit(NotificationEvent.Sep24TransactionTerminal, event);

    this.logger.log(
      `Emitted ${NotificationEvent.Sep24TransactionTerminal} for ` +
      `transaction ${record.id} (status=${internalStatus})`,
    );
  }

  private emitStuck(record: Sep24TransactionRecord, reason: string): void {
    const event = new Sep24TransactionStuckEvent(
      record.id,
      record.anchor_transaction_id,
      record.anchor_domain,
      record.type,
      record.amount,
      record.asset_code,
      record.user_account,
      reason,
    );

    this.eventEmitter.emit(NotificationEvent.Sep24TransactionStuck, event);

    this.logger.warn(
      `Emitted ${NotificationEvent.Sep24TransactionStuck} for ` +
      `transaction ${record.id}`,
    );
  }
}
