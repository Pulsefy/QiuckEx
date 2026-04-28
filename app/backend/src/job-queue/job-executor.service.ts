/**
 * Job Queue System - Job Executor Service
 * 
 * Responsible for polling the database for due jobs and dispatching them to their handlers.
 * Uses @nestjs/schedule for cron-based polling at 10-second intervals.
 * 
 * **Validates: Requirements 4.6, 12.4**
 */

import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { JobRepository } from './job.repository';
import { JobRegistry } from './job-registry.service';
import { CancellationStore } from './cancellation-token';
import { JobQueueMetricsService } from './job-queue-metrics.service';
import { Job, JobStatus, RetryPolicy } from './types';

/**
 * Job Executor Service
 * 
 * This service is responsible for:
 * - Polling the database every 10 seconds for due jobs
 * - Querying jobs where status=pending AND scheduled_at <= NOW AND visibility_timeout expired
 * - Processing up to 100 jobs per poll
 * 
 * Future tasks (3.2-3.5) will implement:
 * - Job locking with visibility timeout
 * - Job execution flow (handler invocation)
 * - Retry scheduling
 * - Stale job recovery on startup
 */
@Injectable()
export class JobExecutor implements OnModuleInit {
  private readonly logger = new Logger(JobExecutor.name);
  private isProcessing = false;

  constructor(
    private readonly repository: JobRepository,
    private readonly registry: JobRegistry,
    private readonly cancellationStore: CancellationStore,
    private readonly metrics: JobQueueMetricsService,
  ) {}

  /**
   * Initialize the executor on module startup
   * 
   * Calls resetStaleJobs() to recover from application crashes or restarts.
   * This resets all jobs with status 'running' to 'pending' so they can be retried.
   * 
   * **Validates: Requirements 12.2, 12.3**
   */
  async onModuleInit(): Promise<void> {
    this.logger.log('JobExecutor initialized');
    
    // Reset stale jobs on startup
    try {
      const resetCount = await this.repository.resetStaleJobs();
      if (resetCount > 0) {
        this.logger.warn(`Reset ${resetCount} stale jobs on startup`);
      } else {
        this.logger.log('No stale jobs found on startup');
      }
    } catch (error) {
      this.logger.error(
        `Failed to reset stale jobs on startup: ${error.message}`,
        error.stack,
      );
      // Don't throw - allow the application to start even if reset fails
    }
  }

  /**
   * Process due jobs on a 10-second cron schedule
   * 
   * Queries for jobs where:
   * - status = 'pending'
   * - scheduled_at <= NOW
   * - visibility_timeout is null or expired
   * 
   * Processes up to 100 jobs per poll to prevent overwhelming the system.
   * 
   * **Validates: Requirements 4.6, 12.4**
   */
  @Cron(CronExpression.EVERY_10_SECONDS)
  async processDueJobs(): Promise<void> {
    // Prevent concurrent execution of the same cron job
    if (this.isProcessing) {
      this.logger.debug('Skipping poll - previous execution still in progress');
      return;
    }

    this.isProcessing = true;

    try {
      // Query for up to 100 due jobs
      const jobs = await this.repository.findDueJobs(100);

      if (jobs.length === 0) {
        this.logger.debug('No due jobs found');
        return;
      }

      this.logger.log(`Found ${jobs.length} due jobs to process`);

      // Process each job
      for (const job of jobs) {
        try {
          await this.executeJob(job);
        } catch (error) {
          this.logger.error(
            `Error executing job ${job.id}: ${error.message}`,
            error.stack,
          );
        }
      }
    } catch (error) {
      this.logger.error(
        `Error processing due jobs: ${error.message}`,
        error.stack,
      );
    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Execute a single job
   * 
   * This method implements the complete job execution flow:
   * 1. Check if job has expired visibility timeout (treat as failure)
   * 2. Lock the job by updating status to 'running' and setting visibility_timeout
   * 3. Record the startedAt timestamp
   * 4. Retrieve handler from JobRegistry
   * 5. Create CancellationToken for the job
   * 6. Invoke handler.execute() with job and cancellation token
   * 7. Handle success: update status to completed, set completedAt
   * 8. Handle failure: increment attempts, set failureReason, calculate retry delay
   * 9. Move to DLQ when attempts >= maxAttempts
   * 
   * @param job - The job to execute
   * 
   * **Validates: Requirements 3.5, 4.1, 4.2, 4.3, 4.4, 4.5, 3.4**
   */
  private async executeJob(job: Job): Promise<void> {
    let policy: RetryPolicy;
    
    try {
      // Get the retry policy for this job type to determine visibility timeout
      policy = this.registry.getPolicy(job.type);

      // Check if this job has an expired visibility timeout
      // This indicates the previous execution attempt timed out or crashed
      if (job.visibilityTimeout && job.visibilityTimeout < new Date()) {
        this.logger.warn(
          `Job ${job.id} has expired visibility timeout (type: ${job.type}, timeout: ${job.visibilityTimeout.toISOString()}). Treating as timeout failure.`,
        );
        
        // Treat expired visibility timeout as a failure
        const timeoutError = new Error(
          `Visibility timeout expired at ${job.visibilityTimeout.toISOString()}`,
        );
        await this.handleJobFailure(job, timeoutError, policy);
        return;
      }

      // Calculate visibility timeout: current time + policy.visibilityTimeoutMs
      const visibilityTimeout = new Date(Date.now() + policy.visibilityTimeoutMs);
      const startedAt = new Date();

      // Lock the job by updating status to 'running' and setting visibility timeout
      // This prevents other executor instances from picking up the same job
      await this.repository.updateJobStatus(job.id, JobStatus.RUNNING, {
        startedAt,
        visibilityTimeout,
      });

      // Update gauge metrics: pending -> running
      this.metrics.updateJobsPendingCount(job.type, -1);
      this.metrics.updateJobsRunningCount(job.type, 1);

      // Structured logging: job started at INFO level
      this.logger.log({
        message: 'Job started',
        jobId: job.id,
        type: job.type,
        attempts: job.attempts + 1,
      });

      // Retrieve handler from JobRegistry
      const handler = this.registry.getHandler(job.type);

      // Create CancellationToken for the job
      const cancellationToken = this.cancellationStore.createToken(job.id);

      // Invoke handler.execute() with job and cancellation token
      await handler.execute(job, cancellationToken);

      // Success: update status to completed, set completedAt
      const completedAt = new Date();
      await this.repository.updateJobStatus(job.id, JobStatus.COMPLETED, {
        completedAt,
      });

      // Calculate execution duration in seconds
      const durationMs = completedAt.getTime() - startedAt.getTime();
      const durationSeconds = durationMs / 1000;

      // Update metrics
      this.metrics.incrementJobsCompleted(job.type);
      this.metrics.updateJobsRunningCount(job.type, -1);
      this.metrics.recordJobExecutionDuration(job.type, durationSeconds);

      // Structured logging: job completed at INFO level
      this.logger.log({
        message: 'Job completed',
        jobId: job.id,
        type: job.type,
        duration: durationMs,
      });

      // Clean up cancellation token
      this.cancellationStore.clearCancellation(job.id);
    } catch (error) {
      // Handle failure: increment attempts, set failureReason, calculate retry delay
      await this.handleJobFailure(job, error, policy);
    }
  }

  /**
   * Handle job failure by incrementing attempts and scheduling retry or moving to DLQ
   * 
   * Handles all types of failures including:
   * - Handler execution errors
   * - Visibility timeout expiration (job took too long or executor crashed)
   * 
   * @param job - The failed job
   * @param error - The error that caused the failure
   * @param policy - The retry policy for this job type
   * 
   * **Validates: Requirements 4.4, 4.5, 3.4**
   */
  private async handleJobFailure(
    job: Job,
    error: Error,
    policy: RetryPolicy,
  ): Promise<void> {
    const newAttempts = job.attempts + 1;
    const failureReason = error.message || 'Unknown error';

    // Structured logging: job failed at ERROR level with stack trace
    this.logger.error({
      message: 'Job failed',
      jobId: job.id,
      type: job.type,
      attempts: newAttempts,
      failureReason,
      stack: error.stack,
    });

    // Check if job has exhausted all retry attempts
    if (newAttempts >= policy.maxAttempts && policy.maxAttempts > 0) {
      // Move to DLQ: mark as failed permanently
      await this.repository.updateJobStatus(job.id, JobStatus.FAILED, {
        attempts: newAttempts,
        failureReason,
        completedAt: new Date(),
      });

      // Update metrics
      this.metrics.incrementJobsFailed(job.type);
      this.metrics.updateJobsRunningCount(job.type, -1);
      this.metrics.updateJobsDlqCount(job.type, 1);

      this.logger.warn(
        `Job ${job.id} moved to DLQ after ${newAttempts} attempts (type: ${job.type})`,
      );

      // Call handler's onFailure hook
      try {
        const handler = this.registry.getHandler(job.type);
        await handler.onFailure(job, error);
      } catch (hookError) {
        this.logger.error(
          `Failed to execute onFailure hook for job ${job.id}: ${hookError.message}`,
          hookError.stack,
        );
      }

      // Clean up cancellation token
      this.cancellationStore.clearCancellation(job.id);
    } else {
      // Schedule retry: calculate retry delay and update scheduledAt
      const retryDelayMs = this.calculateRetryDelay(policy, newAttempts);
      const scheduledAt = new Date(Date.now() + retryDelayMs);

      await this.repository.updateJobStatus(job.id, JobStatus.PENDING, {
        attempts: newAttempts,
        failureReason,
        scheduledAt,
        visibilityTimeout: null, // Clear visibility timeout for retry
      });

      // Update gauge metrics: running -> pending
      this.metrics.updateJobsRunningCount(job.type, -1);
      this.metrics.updateJobsPendingCount(job.type, 1);

      this.logger.log(
        `Job ${job.id} scheduled for retry in ${retryDelayMs}ms (type: ${job.type}, attempt: ${newAttempts}/${policy.maxAttempts})`,
      );

      // Clean up cancellation token
      this.cancellationStore.clearCancellation(job.id);
    }
  }

  /**
   * Calculate retry delay based on retry policy and attempt count
   * 
   * @param policy - The retry policy
   * @param attempts - The current attempt count
   * @returns The delay in milliseconds before the next retry
   */
  private calculateRetryDelay(policy: RetryPolicy, attempts: number): number {
    let delay: number;

    switch (policy.backoffStrategy) {
      case 'fixed':
        delay = policy.initialDelayMs;
        break;
      case 'linear':
        delay = policy.initialDelayMs * attempts;
        break;
      case 'exponential':
        delay = policy.initialDelayMs * Math.pow(2, attempts - 1);
        break;
      default:
        throw new Error(
          `Unknown backoff strategy: ${(policy as RetryPolicy).backoffStrategy}`,
        );
    }

    return Math.min(delay, policy.maxDelayMs);
  }

}
