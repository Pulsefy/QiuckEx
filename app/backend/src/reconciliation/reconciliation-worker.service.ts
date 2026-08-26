import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';
import { CronJob } from 'cron';

import { AppConfigService } from '../config/app-config.service';
import { ReconciliationService } from './reconciliation.service';
import { ReconciliationReport } from './types/reconciliation.types';
import { JobQueueService } from '../job-queue/job-queue.service';
import { JobType } from '../job-queue/types';
import { ReconciliationPayload } from '../job-queue/types/job-payloads.types';

/**
 * ReconciliationWorkerService
 *
 * Runs on a configurable cron schedule (default: every 5 minutes).
 * Enqueues reconciliation jobs via the unified job queue system.
 * The visibility timeout prevents concurrent reconciliation jobs.
 *
 * The worker is self-serialising: if a previous run is still in progress
 * when the next tick fires, the new tick is skipped to prevent thundering
 * herds against the Horizon API.
 */
@Injectable()
export class ReconciliationWorkerService implements OnApplicationBootstrap {
  private readonly logger = new Logger(ReconciliationWorkerService.name);
  private isRunning = false;
  private lastReport: ReconciliationReport | null = null;

  constructor(
    private readonly reconciliationService: ReconciliationService,
    private readonly config: AppConfigService,
    private readonly jobQueueService: JobQueueService,
    private readonly schedulerRegistry: SchedulerRegistry,
  ) {}

  onApplicationBootstrap(): void {
    const cronExpression = this.config.reconciliationCronExpression;
    this.logger.log(`Scheduling reconciliation worker with expression: ${cronExpression}`);

    try {
      const job = new CronJob(cronExpression, async () => {
        await this.handleCron();
      });

      this.schedulerRegistry.addCronJob('reconciliation-worker', job);
      job.start();
    } catch (err) {
      this.logger.error(
        `Failed to schedule reconciliation worker: ${(err as Error).message}`,
        (err as Error).stack,
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Scheduled job — every 5 minutes by default.
  // Override via RECONCILIATION_CRON_EXPRESSION env var for custom scheduling.
  // ---------------------------------------------------------------------------

  async handleCron(): Promise<void> {
    if (this.isRunning) {
      const msg = 'Reconciliation tick skipped — previous run still in progress';
      this.logger.warn(msg);
      this.reconciliationService.recordSkip(msg);
      return;
    }

    this.isRunning = true;
    this.logger.log('Reconciliation cron tick started - enqueuing job');

    try {
      const batchSize = this.config.reconciliationBatchSize;

      // Enqueue reconciliation job via JobQueueService
      const payload: ReconciliationPayload = {
        batchSize,
      };

      const jobId = await this.jobQueueService.enqueue(
        JobType.RECONCILIATION,
        payload,
      );

      this.logger.log(`Reconciliation job enqueued: ${jobId} (batchSize: ${batchSize})`);
    } catch (err) {
      const errorMsg = `Failed to enqueue reconciliation job: ${(err as Error).message}`;
      this.logger.error(errorMsg, (err as Error).stack);
      this.reconciliationService.recordFailure(errorMsg);
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
