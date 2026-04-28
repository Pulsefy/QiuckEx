/**
 * Job Queue System - Metrics Service
 * 
 * Provides Prometheus metrics for job lifecycle events.
 * 
 * **Validates: Requirements 13.1, 13.2, 13.3**
 */

import { Injectable, OnModuleInit } from '@nestjs/common';
import * as client from 'prom-client';
import { JobType } from './types';
import { MetricsService } from '../metrics/metrics.service';

/**
 * Job Queue Metrics Service
 * 
 * Provides Prometheus metrics for:
 * - Counter metrics: jobs_enqueued_total, jobs_completed_total, jobs_failed_total, jobs_cancelled_total
 * - Gauge metrics: jobs_pending_count, jobs_running_count, jobs_dlq_count
 * - Histogram metric: job_execution_duration_seconds
 * 
 * All metrics are labeled by job type for granular monitoring.
 */
@Injectable()
export class JobQueueMetricsService implements OnModuleInit {
  // Counter metrics
  private jobsEnqueuedTotal: client.Counter<string>;
  private jobsCompletedTotal: client.Counter<string>;
  private jobsFailedTotal: client.Counter<string>;
  private jobsCancelledTotal: client.Counter<string>;

  // Gauge metrics
  private jobsPendingCount: client.Gauge<string>;
  private jobsRunningCount: client.Gauge<string>;
  private jobsDlqCount: client.Gauge<string>;

  // Histogram metric
  private jobExecutionDuration: client.Histogram<string>;

  private initialized = false;

  constructor(private readonly metricsService: MetricsService) {}

  /**
   * Initialize all metrics on module startup
   * 
   * Registers metrics with the Prometheus registry from MetricsService.
   */
  onModuleInit() {
    try {
      const register = this.metricsService.getRegistry();

      // Counter: jobs_enqueued_total
      this.jobsEnqueuedTotal = new client.Counter({
        name: 'jobs_enqueued_total',
        help: 'Total number of jobs enqueued',
        labelNames: ['type'],
        registers: [register],
      });

      // Counter: jobs_completed_total
      this.jobsCompletedTotal = new client.Counter({
        name: 'jobs_completed_total',
        help: 'Total number of jobs completed successfully',
        labelNames: ['type'],
        registers: [register],
      });

      // Counter: jobs_failed_total
      this.jobsFailedTotal = new client.Counter({
        name: 'jobs_failed_total',
        help: 'Total number of jobs that failed permanently (moved to DLQ)',
        labelNames: ['type'],
        registers: [register],
      });

      // Counter: jobs_cancelled_total
      this.jobsCancelledTotal = new client.Counter({
        name: 'jobs_cancelled_total',
        help: 'Total number of jobs cancelled',
        labelNames: ['type'],
        registers: [register],
      });

      // Gauge: jobs_pending_count
      this.jobsPendingCount = new client.Gauge({
        name: 'jobs_pending_count',
        help: 'Current number of pending jobs',
        labelNames: ['type'],
        registers: [register],
      });

      // Gauge: jobs_running_count
      this.jobsRunningCount = new client.Gauge({
        name: 'jobs_running_count',
        help: 'Current number of running jobs',
        labelNames: ['type'],
        registers: [register],
      });

      // Gauge: jobs_dlq_count
      this.jobsDlqCount = new client.Gauge({
        name: 'jobs_dlq_count',
        help: 'Current number of jobs in dead letter queue',
        labelNames: ['type'],
        registers: [register],
      });

      // Histogram: job_execution_duration_seconds
      this.jobExecutionDuration = new client.Histogram({
        name: 'job_execution_duration_seconds',
        help: 'Duration of job execution in seconds',
        labelNames: ['type'],
        buckets: [0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600], // Up to 10 minutes
        registers: [register],
      });

      this.initialized = true;
    } catch (error) {
      console.error('Failed to initialize job queue metrics:', error);
      this.initialized = false;
    }
  }

  /**
   * Increment jobs_enqueued_total counter
   * 
   * Called when a job is enqueued.
   * 
   * @param type - Job type
   */
  incrementJobsEnqueued(type: JobType): void {
    if (!this.initialized || !this.jobsEnqueuedTotal) {
      return;
    }

    try {
      this.jobsEnqueuedTotal.labels(type).inc();
    } catch (error) {
      // Silently fail to avoid breaking job enqueue
    }
  }

  /**
   * Increment jobs_completed_total counter
   * 
   * Called when a job completes successfully.
   * 
   * @param type - Job type
   */
  incrementJobsCompleted(type: JobType): void {
    if (!this.initialized || !this.jobsCompletedTotal) {
      return;
    }

    try {
      this.jobsCompletedTotal.labels(type).inc();
    } catch (error) {
      // Silently fail
    }
  }

  /**
   * Increment jobs_failed_total counter
   * 
   * Called when a job fails permanently (moved to DLQ).
   * 
   * @param type - Job type
   */
  incrementJobsFailed(type: JobType): void {
    if (!this.initialized || !this.jobsFailedTotal) {
      return;
    }

    try {
      this.jobsFailedTotal.labels(type).inc();
    } catch (error) {
      // Silently fail
    }
  }

  /**
   * Increment jobs_cancelled_total counter
   * 
   * Called when a job is cancelled.
   * 
   * @param type - Job type
   */
  incrementJobsCancelled(type: JobType): void {
    if (!this.initialized || !this.jobsCancelledTotal) {
      return;
    }

    try {
      this.jobsCancelledTotal.labels(type).inc();
    } catch (error) {
      // Silently fail
    }
  }

  /**
   * Update jobs_pending_count gauge
   * 
   * Called when a job transitions to/from pending status.
   * 
   * @param type - Job type
   * @param delta - Change in count (+1 or -1)
   */
  updateJobsPendingCount(type: JobType, delta: number): void {
    if (!this.initialized || !this.jobsPendingCount) {
      return;
    }

    try {
      if (delta > 0) {
        this.jobsPendingCount.labels(type).inc(delta);
      } else if (delta < 0) {
        this.jobsPendingCount.labels(type).dec(Math.abs(delta));
      }
    } catch (error) {
      // Silently fail
    }
  }

  /**
   * Update jobs_running_count gauge
   * 
   * Called when a job transitions to/from running status.
   * 
   * @param type - Job type
   * @param delta - Change in count (+1 or -1)
   */
  updateJobsRunningCount(type: JobType, delta: number): void {
    if (!this.initialized || !this.jobsRunningCount) {
      return;
    }

    try {
      if (delta > 0) {
        this.jobsRunningCount.labels(type).inc(delta);
      } else if (delta < 0) {
        this.jobsRunningCount.labels(type).dec(Math.abs(delta));
      }
    } catch (error) {
      // Silently fail
    }
  }

  /**
   * Update jobs_dlq_count gauge
   * 
   * Called when a job is moved to/from the dead letter queue.
   * 
   * @param type - Job type
   * @param delta - Change in count (+1 or -1)
   */
  updateJobsDlqCount(type: JobType, delta: number): void {
    if (!this.initialized || !this.jobsDlqCount) {
      return;
    }

    try {
      if (delta > 0) {
        this.jobsDlqCount.labels(type).inc(delta);
      } else if (delta < 0) {
        this.jobsDlqCount.labels(type).dec(Math.abs(delta));
      }
    } catch (error) {
      // Silently fail
    }
  }

  /**
   * Record job execution duration
   * 
   * Called when a job completes (successfully or with failure).
   * 
   * @param type - Job type
   * @param durationSeconds - Duration in seconds
   */
  recordJobExecutionDuration(type: JobType, durationSeconds: number): void {
    if (!this.initialized || !this.jobExecutionDuration) {
      return;
    }

    try {
      this.jobExecutionDuration.labels(type).observe(durationSeconds);
    } catch (error) {
      // Silently fail
    }
  }
}
