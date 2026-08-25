/**
 * SEP-24 Status Poll Handler
 *
 * Implements the JobHandler interface for the SEP-24 anchor transaction
 * status poll job type.
 *
 * Each execution delegates to Sep24PollingService.runPollCycle() which polls
 * every in-flight SEP-24 transaction, persists state changes, emits events,
 * and flags stuck transactions.
 *
 * The handler is registered with maxAttempts=1 (no retries) because the next
 * cron tick will re-poll naturally. Individual anchor-level transient errors
 * are handled per-transaction inside Sep24PollingService rather than at the
 * job level.
 */

import { Injectable, Logger } from '@nestjs/common';
import { JobHandler, Job, CancellationToken } from '../types';
import { Sep24StatusPollPayload } from '../types/job-payloads.types';
import { Sep24PollingService } from '../../fiat-ramps/sep24-polling.service';
import { PermanentJobError } from './webhook-delivery.handler';

@Injectable()
export class Sep24StatusPollHandler implements JobHandler<Sep24StatusPollPayload> {
  private readonly logger = new Logger(Sep24StatusPollHandler.name);

  constructor(private readonly sep24PollingService: Sep24PollingService) {}

  /**
   * Run a full SEP-24 anchor status poll cycle.
   *
   * @param job               - The poll job (contains triggeredBy in payload).
   * @param _cancellationToken - Not used; each per-transaction poll is short-lived.
   */
  async execute(
    job: Job<Sep24StatusPollPayload>,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _cancellationToken: CancellationToken,
  ): Promise<void> {
    const { triggeredBy } = job.payload;

    this.logger.log(
      `Starting SEP-24 status poll cycle ` +
      `(jobId: ${job.id}, triggeredBy: ${triggeredBy})`,
    );

    const summary = await this.sep24PollingService.runPollCycle();

    this.logger.log(
      `SEP-24 poll cycle complete (jobId: ${job.id}) — ` +
      `processed:${summary.processed} updated:${summary.updated} ` +
      `terminal:${summary.terminal} stuck:${summary.stuck} failed:${summary.failed}`,
    );

    if (summary.stuck > 0) {
      this.logger.warn(
        `${summary.stuck} SEP-24 transaction(s) flagged as stuck ` +
        `(jobId: ${job.id}) — operator review required`,
      );
    }
  }

  /**
   * Validate the poll payload.
   * Only `triggeredBy` is required and must be a known value.
   */
  async validate(payload: Sep24StatusPollPayload): Promise<void> {
    const allowed: Sep24StatusPollPayload['triggeredBy'][] = ['cron', 'manual'];

    if (!payload.triggeredBy || !allowed.includes(payload.triggeredBy)) {
      throw new PermanentJobError(
        `Invalid SEP-24 poll payload: triggeredBy must be one of ${allowed.join(', ')}`,
      );
    }
  }

  /**
   * Handle permanent failure of the poll job.
   * Logs the failure; the next cron tick will naturally re-attempt.
   */
  async onFailure(
    job: Job<Sep24StatusPollPayload>,
    error: Error,
  ): Promise<void> {
    this.logger.error(
      `SEP-24 status poll job permanently failed ` +
      `(jobId: ${job.id}, triggeredBy: ${job.payload.triggeredBy}): ${error.message}`,
      error.stack,
    );
  }
}
