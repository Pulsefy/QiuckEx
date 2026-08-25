/**
 * SEP-24 Polling Worker Service
 *
 * Scheduled driver that enqueues a SEP-24 status-poll job every minute via
 * the unified job-queue system.  Follows the same self-serialising pattern as
 * ReconciliationWorkerService to prevent thundering-herd against anchors.
 */

import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { JobQueueService } from '../job-queue/job-queue.service';
import { JobType } from '../job-queue/types';
import { Sep24StatusPollPayload } from '../job-queue/types/job-payloads.types';

@Injectable()
export class Sep24PollingWorkerService {
  private readonly logger = new Logger(Sep24PollingWorkerService.name);
  private isRunning = false;

  constructor(private readonly jobQueueService: JobQueueService) {}

  /**
   * Runs every minute and enqueues a single SEP-24_STATUS_POLL job.
   *
   * The job-queue's visibility timeout (see job-queue-initializer.service.ts)
   * ensures at most one poll cycle runs at a time, even if the previous cycle
   * is still executing when the next cron tick fires.
   */
  @Cron(CronExpression.EVERY_MINUTE, {
    name: 'sep24-poll-worker',
    timeZone: 'UTC',
  })
  async handleCron(): Promise<void> {
    if (this.isRunning) {
      this.logger.warn('SEP-24 poll tick skipped — previous enqueue still in progress');
      return;
    }

    this.isRunning = true;

    try {
      const payload: Sep24StatusPollPayload = { triggeredBy: 'cron' };
      const jobId = await this.jobQueueService.enqueue<Sep24StatusPollPayload>(
        JobType.SEP24_STATUS_POLL,
        payload,
      );

      this.logger.log(`SEP-24 status-poll job enqueued: ${jobId}`);
    } catch (err) {
      this.logger.error(
        `Failed to enqueue SEP-24 status-poll job: ${(err as Error).message}`,
        (err as Error).stack,
      );
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Manually trigger a poll cycle without waiting for the next cron tick.
   * Useful from admin endpoints or integration tests.
   */
  async triggerManually(): Promise<string> {
    const payload: Sep24StatusPollPayload = { triggeredBy: 'manual' };
    return this.jobQueueService.enqueue<Sep24StatusPollPayload>(
      JobType.SEP24_STATUS_POLL,
      payload,
    );
  }
}
