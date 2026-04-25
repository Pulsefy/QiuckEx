/**
 * Job Queue System - Reconciliation Handler
 * 
 * Implements the JobHandler interface for reconciliation jobs.
 * Compares internal state with Horizon API and persists reconciliation reports.
 * 
 * Requirements: 10.3, 10.5, 15.4, 15.5
 */

import { Injectable, Logger } from '@nestjs/common';
import { JobHandler, Job, CancellationToken } from '../types';
import { ReconciliationPayload } from '../types/job-payloads.types';
import { ReconciliationService } from '../../reconciliation/reconciliation.service';
import { ReconciliationReport } from '../../reconciliation/types/reconciliation.types';
import { PermanentJobError } from './webhook-delivery.handler';

/**
 * Reconciliation Handler
 * 
 * Executes reconciliation runs to compare internal database state with
 * the Stellar blockchain via Horizon API. Persists reconciliation reports
 * with any discrepancies found.
 * 
 * This handler is designed to run with maxAttempts=1 (no retries) since
 * reconciliation is idempotent and will be retried on the next cron tick.
 */
@Injectable()
export class ReconciliationHandler implements JobHandler<ReconciliationPayload> {
  private readonly logger = new Logger(ReconciliationHandler.name);

  constructor(
    private readonly reconciliationService: ReconciliationService,
  ) {}

  /**
   * Execute reconciliation run
   * 
   * Delegates to ReconciliationService to perform the actual reconciliation
   * logic. The service compares internal state with Horizon API and returns
   * a detailed report with any discrepancies.
   * 
   * @param job - The reconciliation job
   * @param cancellationToken - Token to check for cancellation (not used for reconciliation)
   * @throws Error on transient failures (Horizon unavailable, network errors)
   * @throws PermanentJobError on validation failures
   * 
   * **Validates: Requirements 10.3, 10.5**
   */
  async execute(
    job: Job<ReconciliationPayload>,
    cancellationToken: CancellationToken,
  ): Promise<void> {
    const { batchSize, startLedger, endLedger } = job.payload;

    this.logger.log(
      `Starting reconciliation run (jobId: ${job.id}, batchSize: ${batchSize}, ` +
      `startLedger: ${startLedger ?? 'none'}, endLedger: ${endLedger ?? 'none'})`,
    );

    try {
      // Run reconciliation - this returns a detailed report
      const report: ReconciliationReport = await this.reconciliationService.runReconciliation(
        batchSize,
      );

      // Log summary of reconciliation results
      this.logger.log(
        `Reconciliation completed (jobId: ${job.id}, runId: ${report.runId}, ` +
        `duration: ${report.durationMs}ms, ` +
        `escrows: ${report.escrows.processed} processed, ${report.escrows.irreconcilable} irreconcilable, ` +
        `payments: ${report.payments.processed} processed, ${report.payments.irreconcilable} irreconcilable)`,
      );

      // Warn if any irreconcilable records were found
      const totalIrreconcilable = report.escrows.irreconcilable + report.payments.irreconcilable;
      if (totalIrreconcilable > 0) {
        this.logger.warn(
          `Reconciliation found ${totalIrreconcilable} irreconcilable record(s) - ` +
          `manual review required (jobId: ${job.id}, runId: ${report.runId})`,
        );
      }

      // Note: The ReconciliationService already persists the report internally
      // and logs detailed results. The report is also stored in the job system
      // via the lastReport field in ReconciliationWorkerService.
    } catch (error) {
      // Log error with context
      this.logger.error(
        `Reconciliation failed (jobId: ${job.id}): ${error.message}`,
        error.stack,
      );

      // Re-throw to trigger job failure handling
      // Most reconciliation errors are transient (Horizon unavailable, network issues)
      throw error;
    }
  }

  /**
   * Validate reconciliation payload
   * 
   * Checks that required fields are present:
   * - batchSize: Number of records to process per batch (must be positive)
   * 
   * Optional fields:
   * - startLedger: Starting ledger sequence (if provided, must be positive)
   * - endLedger: Ending ledger sequence (if provided, must be >= startLedger)
   * 
   * @param payload - The reconciliation payload
   * @throws PermanentJobError if validation fails
   * 
   * **Validates: Requirements 10.3, 15.4, 15.5**
   */
  async validate(payload: ReconciliationPayload): Promise<void> {
    const errors: string[] = [];

    // Validate batchSize
    if (typeof payload.batchSize !== 'number') {
      errors.push('batchSize is required and must be a number');
    } else if (payload.batchSize <= 0) {
      errors.push('batchSize must be greater than 0');
    } else if (!Number.isInteger(payload.batchSize)) {
      errors.push('batchSize must be an integer');
    }

    // Validate startLedger (optional)
    if (payload.startLedger !== undefined) {
      if (typeof payload.startLedger !== 'number') {
        errors.push('startLedger must be a number');
      } else if (payload.startLedger <= 0) {
        errors.push('startLedger must be greater than 0');
      } else if (!Number.isInteger(payload.startLedger)) {
        errors.push('startLedger must be an integer');
      }
    }

    // Validate endLedger (optional)
    if (payload.endLedger !== undefined) {
      if (typeof payload.endLedger !== 'number') {
        errors.push('endLedger must be a number');
      } else if (payload.endLedger <= 0) {
        errors.push('endLedger must be greater than 0');
      } else if (!Number.isInteger(payload.endLedger)) {
        errors.push('endLedger must be an integer');
      }
    }

    // Validate ledger range consistency
    if (
      payload.startLedger !== undefined &&
      payload.endLedger !== undefined &&
      payload.endLedger < payload.startLedger
    ) {
      errors.push('endLedger must be greater than or equal to startLedger');
    }

    if (errors.length > 0) {
      throw new PermanentJobError(`Validation failed: ${errors.join(', ')}`);
    }
  }

  /**
   * Handle reconciliation failure
   * 
   * Logs reconciliation failure for monitoring and alerting.
   * Since reconciliation runs on a cron schedule, failures will be retried
   * on the next tick. No additional cleanup is needed.
   * 
   * @param job - The failed job
   * @param error - The error that caused the failure
   * 
   * **Validates: Requirements 10.5**
   */
  async onFailure(job: Job<ReconciliationPayload>, error: Error): Promise<void> {
    this.logger.error(
      `Reconciliation permanently failed (jobId: ${job.id}, ` +
      `batchSize: ${job.payload.batchSize}): ${error.message}`,
      error.stack,
    );

    // Note: Reconciliation failures are typically transient (Horizon unavailable)
    // and will be retried on the next cron tick. No additional action needed here.
    // Operators should monitor reconciliation failure metrics and alerts.
  }
}
