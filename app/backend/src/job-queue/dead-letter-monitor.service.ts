/**
 * Job Queue System - Dead Letter Queue Monitor
 *
 * Periodically samples per-job-type queue depth, dead letter depth, and the
 * age of the oldest pending/dead-lettered job, publishing them as metrics.
 * Fires (and clears) a threshold alert when dead letter depth or oldest-job
 * age crosses configurable limits, so a sustained backlog for a job type is
 * distinguishable from a single, quickly-cleared failure.
 */

import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { AppConfigService } from '../config';
import { JobRepository } from './job.repository';
import { JobQueueMetricsService } from './job-queue-metrics.service';
import { JobStatus, JobType } from './types';

@Injectable()
export class DeadLetterQueueMonitorService implements OnModuleInit {
  private readonly logger = new Logger(DeadLetterQueueMonitorService.name);

  /** Tracks whether an alert is currently firing, keyed by `${type}:${reason}`, to log only on state transitions. */
  private readonly activeAlerts = new Set<string>();

  constructor(
    private readonly repository: JobRepository,
    private readonly metrics: JobQueueMetricsService,
    private readonly config: AppConfigService,
  ) {}

  onModuleInit(): void {
    if (this.config.dlqMonitorEnabled) {
      void this.checkQueueHealth();
    }
  }

  @Cron(CronExpression.EVERY_MINUTE)
  async checkQueueHealth(): Promise<void> {
    if (!this.config.dlqMonitorEnabled) {
      return;
    }

    const now = new Date();
    const depthThreshold = this.config.dlqAlertDepthThreshold;
    const ageThresholdSeconds = Math.floor(this.config.dlqAlertAgeThresholdMs / 1000);

    for (const type of Object.values(JobType)) {
      try {
        await this.checkJobType(type, now, depthThreshold, ageThresholdSeconds);
      } catch (error) {
        this.logger.warn(
          `Dead letter queue health check failed for type ${type}: ${(error as Error).message}`,
        );
      }
    }
  }

  private async checkJobType(
    type: JobType,
    now: Date,
    depthThreshold: number,
    ageThresholdSeconds: number,
  ): Promise<void> {
    const [pendingOldestAgeSeconds, dlqDepth, dlqOldestAgeSeconds] = await Promise.all([
      this.repository.getOldestAgeSeconds(type, JobStatus.PENDING, now),
      this.repository.countByTypeAndStatus(type, JobStatus.FAILED),
      this.repository.getOldestAgeSeconds(type, JobStatus.FAILED, now),
    ]);

    this.metrics.setPendingOldestAgeSeconds(type, pendingOldestAgeSeconds ?? 0);
    this.metrics.setDlqOldestAgeSeconds(type, dlqOldestAgeSeconds ?? 0);

    const depthBreached = dlqDepth >= depthThreshold;
    const ageBreached = dlqOldestAgeSeconds !== null && dlqOldestAgeSeconds >= ageThresholdSeconds;

    this.updateAlert(type, 'depth', depthBreached, {
      dlqDepth,
      depthThreshold,
    });
    this.updateAlert(type, 'age', ageBreached, {
      dlqOldestAgeSeconds,
      ageThresholdSeconds,
    });
  }

  /** Sets the alert gauge and logs only when the alert transitions between firing and clear. */
  private updateAlert(
    type: JobType,
    reason: 'depth' | 'age',
    firing: boolean,
    context: Record<string, unknown>,
  ): void {
    const key = `${type}:${reason}`;
    const wasFiring = this.activeAlerts.has(key);

    this.metrics.setDlqAlertActive(type, reason, firing);

    if (firing && !wasFiring) {
      this.activeAlerts.add(key);
      this.logger.warn({
        message: 'Dead letter queue alert firing',
        type,
        reason,
        ...context,
      });
    } else if (!firing && wasFiring) {
      this.activeAlerts.delete(key);
      this.logger.log({
        message: 'Dead letter queue alert cleared',
        type,
        reason,
        ...context,
      });
    }
  }
}
