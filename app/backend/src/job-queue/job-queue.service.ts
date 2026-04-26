/**
 * Job Queue System - Job Queue Service
 * 
 * Main public API for the unified job queue system.
 * Provides methods for enqueuing, cancelling, and querying jobs.
 * 
 * **Validates: Requirements 1.5, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 6.1, 6.2, 15.2, 15.3**
 */

import { Injectable, Logger } from '@nestjs/common';
import { JobRepository, JobFilters, PaginatedJobs } from './job.repository';
import { JobRegistry } from './job-registry.service';
import { CancellationStore } from './cancellation-token';
import { JobQueueMetricsService } from './job-queue-metrics.service';
import { Job, JobType, JobStatus } from './types';

/**
 * Error thrown when attempting to enqueue a job with an unregistered type
 */
export class UnregisteredJobTypeError extends Error {
  constructor(type: JobType) {
    super(`Job type '${type}' is not registered`);
    this.name = 'UnregisteredJobTypeError';
  }
}

/**
 * Error thrown when payload validation fails
 */
export class PayloadValidationError extends Error {
  constructor(message: string) {
    super(`Payload validation failed: ${message}`);
    this.name = 'PayloadValidationError';
  }
}

/**
 * Main service for job queue operations
 * 
 * This service provides the public API for:
 * - Enqueuing jobs (immediate or delayed)
 * - Cancelling jobs
 * - Querying job status and history
 * 
 * It uses:
 * - JobRepository for persistence
 * - JobRegistry for validation and handler lookup
 * - CancellationStore for cancellation management
 */
@Injectable()
export class JobQueueService {
  private readonly logger = new Logger(JobQueueService.name);

  constructor(
    private readonly repository: JobRepository,
    private readonly registry: JobRegistry,
    private readonly cancellationStore: CancellationStore,
    private readonly metrics: JobQueueMetricsService,
  ) {}

  /**
   * Enqueue a job for immediate execution
   * 
   * Creates a new job with the current timestamp as scheduledAt.
   * The job will be picked up by the JobExecutor on the next poll.
   * 
   * @param type - Job type (must be registered)
   * @param payload - Job-specific payload data
   * @returns The created job ID
   * @throws UnregisteredJobTypeError if job type is not registered
   * @throws PayloadValidationError if payload validation fails
   * 
   * **Validates: Requirements 2.1, 2.3, 2.4, 1.5, 15.2, 15.3**
   */
  async enqueue<TPayload = unknown>(
    type: JobType,
    payload: TPayload,
  ): Promise<string> {
    return this.enqueueDelayed(type, payload, new Date());
  }

  /**
   * Enqueue a job for delayed execution
   * 
   * Creates a new job with a future scheduledAt timestamp.
   * The job will be picked up by the JobExecutor when scheduledAt is reached.
   * 
   * @param type - Job type (must be registered)
   * @param payload - Job-specific payload data
   * @param scheduledAt - When the job should execute
   * @returns The created job ID
   * @throws UnregisteredJobTypeError if job type is not registered
   * @throws PayloadValidationError if payload validation fails
   * 
   * **Validates: Requirements 2.2, 2.3, 2.4, 2.5, 2.6, 1.5, 15.2, 15.3**
   */
  async enqueueDelayed<TPayload = unknown>(
    type: JobType,
    payload: TPayload,
    scheduledAt: Date,
  ): Promise<string> {
    // Requirement 1.5: Reject enqueue for unregistered job types
    if (!this.registry.isRegistered(type)) {
      this.logger.error(`Attempted to enqueue unregistered job type: ${type}`);
      throw new UnregisteredJobTypeError(type);
    }

    // Requirement 15.2, 15.3: Validate payload against job type schema
    try {
      const handler = this.registry.getHandler(type);
      await handler.validate(payload);
    } catch (error) {
      this.logger.error(
        `Payload validation failed for job type ${type}: ${error.message}`,
        error.stack,
      );
      throw new PayloadValidationError(error.message);
    }

    // Get retry policy for this job type
    const policy = this.registry.getPolicy(type);

    // Requirement 2.3: Persist job with status "pending"
    const job = await this.repository.createJob<TPayload>(
      type,
      payload,
      policy.maxAttempts,
      scheduledAt,
    );

    // Increment jobs_enqueued_total metric
    this.metrics.incrementJobsEnqueued(type);
    
    // Update jobs_pending_count gauge
    this.metrics.updateJobsPendingCount(type, 1);

    // Structured logging: job enqueued at INFO level
    this.logger.log({
      message: 'Job enqueued',
      jobId: job.id,
      type,
      scheduledAt: scheduledAt.toISOString(),
    });

    // Requirement 2.5: Return unique job identifier
    return job.id;
  }

  /**
   * Request cancellation of a job
   * 
   * For pending jobs: Updates status to 'cancelled' immediately
   * For running jobs: Sets a cancellation token that the handler can check
   * For completed/failed/cancelled jobs: No-op (already terminal state)
   * 
   * @param jobId - The job ID to cancel
   * @throws Error if job not found
   * 
   * **Validates: Requirements 6.1, 6.2, 6.3**
   */
  async cancel(jobId: string): Promise<void> {
    const job = await this.repository.findById(jobId);

    if (!job) {
      throw new Error(`Job not found: ${jobId}`);
    }

    // Requirement 6.2: Cancel pending jobs immediately
    if (job.status === JobStatus.PENDING) {
      await this.repository.updateJobStatus(jobId, JobStatus.CANCELLED, {
        completedAt: new Date(),
      });
      
      // Increment jobs_cancelled_total metric
      this.metrics.incrementJobsCancelled(job.type);
      
      // Update gauge metrics
      this.metrics.updateJobsPendingCount(job.type, -1);
      
      // Structured logging: job cancelled at INFO level
      this.logger.log({
        message: 'Job cancelled',
        jobId,
        type: job.type,
      });
      return;
    }

    // Requirement 6.3: Set cancellation token for running jobs
    if (job.status === JobStatus.RUNNING) {
      this.cancellationStore.requestCancellation(jobId);
      this.logger.log(`Cancellation requested for running job: ${jobId}`);
      return;
    }

    // Job is already in a terminal state (completed, failed, cancelled)
    this.logger.debug(
      `Cannot cancel job ${jobId} - already in terminal state: ${job.status}`,
    );
  }

  /**
   * Get detailed information for a specific job
   * 
   * @param jobId - The job ID
   * @returns The job, or null if not found
   * 
   * **Validates: Requirement 5.2** (via admin controller)
   */
  async getJob<TPayload = unknown>(jobId: string): Promise<Job<TPayload> | null> {
    return this.repository.findById<TPayload>(jobId);
  }

  /**
   * List jobs with optional filters
   * 
   * Supports filtering by:
   * - Job type
   * - Job status
   * - Date range (createdAfter, createdBefore)
   * - Pagination (limit, offset)
   * 
   * @param filters - Query filters
   * @returns Paginated job results
   * 
   * **Validates: Requirements 5.1, 5.5** (via admin controller)
   */
  async listJobs(filters: JobFilters = {}): Promise<PaginatedJobs> {
    return this.repository.listJobs(filters);
  }
}
