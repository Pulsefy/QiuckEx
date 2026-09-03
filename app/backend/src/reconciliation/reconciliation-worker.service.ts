import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
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
 * Runs reconciliation on a configurable schedule (BE-124) — the cron
 * expression defaults to every 5 minutes and can be overridden via
 * RECONCILIATION_CRON_EXPRESSION, with the whole worker toggled via
 * RECONCILIATION_ENABLED.
 *
 * Each tick enqueues a reconciliation job through the unified job queue
 * system; the actual run (and its persisted summary) is handled by the
 * ReconciliationHandler. The worker is self-serialising: if a previous run is
 * still in progress when the next tick fires, the tick is skipped and recorded
 * so consecutive skipped/failed runs are alertable (BE-124).
 */
@Injectable()
export class ReconciliationWorkerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ReconciliationWorkerService.name);
  private cronJob: CronJob | null = null;
  private isRunning = false;
  private lastReport: ReconciliationReport | null = null;

  constructor(
    private readonly reconciliationService: ReconciliationService,
    private readonly config: AppConfigService,
    private readonly jobQueueService: JobQueueService,
  ) {}

  // ---------------------------------------------------------------------------
  // Scheduling (BE-124) — dynamic cron from RECONCILIATION_CRON_EXPRESSION so
  // the schedule is configurable without a deploy, instead of the previous
  // hard-coded every-5-minutes decorator.
  // ---------------------------------------------------------------------------

  onModuleInit(): void {
    if (!this.config.reconciliationEnabled) {
      this.logger.log(
        'Scheduled reconciliation worker disabled via RECONCILIATION_ENABLED',
      );
      return;
    }

    const expression = this.config.reconciliationCronExpression;
    try {
      this.cronJob = new CronJob(
        expression,
        () => void this.handleTick(),
        null,
        true,
        'UTC',
      );
      this.logger.log(
        `Scheduled reconciliation worker initialized (cron: ${expression})`,
      );
    } catch (err) {
      this.logger.error(
        `Failed to initialize reconciliation worker cron ('${expression}'): ${(err as Error).message}`,
      );
    }
  }

  onModuleDestroy(): void {
    if (this.cronJob) {
      this.cronJob.stop();
      this.cronJob = null;
      this.logger.log('Scheduled reconciliation worker stopped');
    }
  }

  // ---------------------------------------------------------------------------
  // Cron tick — enqueue a reconciliation job.
  // ---------------------------------------------------------------------------

  private async handleTick(): Promise<void> {
    if (this.isRunning) {
      this.logger.warn(
        'Reconciliation tick skipped — previous run still in progress',
      );
      await this.reconciliationService.recordSkippedRun(
        'Previous reconciliation run still in progress',
      );
      return;
    }

    this.isRunning = true;
    this.logger.log('Reconciliation cron tick started - enqueuing job');

    try {
      const batchSize = this.config.reconciliationBatchSize;
      const payload: ReconciliationPayload = {
        batchSize,
        // startLedger and endLedger are optional - not used in current implementation
      };

      const jobId = await this.jobQueueService.enqueue(
        JobType.RECONCILIATION,
        payload,
      );

      this.logger.log(`Reconciliation job enqueued: ${jobId} (batchSize: ${batchSize})`);
    } catch (err) {
      const message = (err as Error).message;
      this.logger.error(
        `Failed to enqueue reconciliation job: ${message}`,
        (err as Error).stack,
      );
      await this.reconciliationService.recordFailedRun(message, {
        batchSize: this.config.reconciliationBatchSize,
      });
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
      try {
        this.lastReport = await this.reconciliationService.runReconciliation(batchSize);
        return this.lastReport;
      } catch (err) {
        const message = (err as Error).message;
        this.logger.error(
          `Manual reconciliation run failed: ${message}`,
          (err as Error).stack,
        );
        await this.reconciliationService.recordFailedRun(message, { batchSize });
        throw err;
      }
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