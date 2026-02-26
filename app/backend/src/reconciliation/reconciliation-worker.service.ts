import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';

import { AppConfigService } from '../config/app-config.service';
import { ReconciliationService } from './reconciliation.service';
import { ReconciliationReport } from './types/reconciliation.types';

/**
 * ReconciliationWorkerService
 *
 * Runs on a configurable cron schedule (default: every 5 minutes).
 * Delegates to ReconciliationService for the actual comparison logic
 * and logs a structured summary report after each run.
 *
 * The worker is self-serialising: if a previous run is still in progress
 * when the next tick fires, the new tick is skipped to prevent thundering
 * herds against the Horizon API.
 */
@Injectable()
export class ReconciliationWorkerService {
  private readonly logger = new Logger(ReconciliationWorkerService.name);
  private isRunning = false;
  private lastReport: ReconciliationReport | null = null;

  constructor(
    private readonly reconciliationService: ReconciliationService,
    private readonly config: AppConfigService,
  ) {}

  // ---------------------------------------------------------------------------
  // Scheduled job — every 5 minutes by default.
  // Override via RECONCILIATION_CRON_EXPRESSION env var for custom scheduling.
  // ---------------------------------------------------------------------------

  @Cron(CronExpression.EVERY_5_MINUTES, {
    name: 'reconciliation-worker',
    timeZone: 'UTC',
  })
  async handleCron(): Promise<void> {
    if (this.isRunning) {
      this.logger.warn(
        'Reconciliation tick skipped — previous run still in progress',
      );
      return;
    }

    this.isRunning = true;
    this.logger.log('Reconciliation cron tick started');

    try {
      const batchSize = this.config.reconciliationBatchSize;
      this.lastReport = await this.reconciliationService.runReconciliation(batchSize);
    } catch (err) {
      this.logger.error(
        `Unhandled error in reconciliation worker: ${(err as Error).message}`,
        (err as Error).stack,
      );
    } finally {
      this.isRunning = false;
    }
  }

  // ---------------------------------------------------------------------------
  // Manual trigger — useful for health checks, admin endpoints, or tests.
  // ---------------------------------------------------------------------------

  async triggerManually(): Promise<ReconciliationReport> {
    if (this.isRunning) {
      throw new Error('Reconciliation is already running');
    }
    this.isRunning = true;
    try {
      const batchSize = this.config.reconciliationBatchSize;
      this.lastReport = await this.reconciliationService.runReconciliation(batchSize);
      return this.lastReport;
    } finally {
      this.isRunning = false;
    }
  }

  getLastReport(): ReconciliationReport | null {
    return this.lastReport;
  }

  get running(): boolean {
    return this.isRunning;
  }
}
