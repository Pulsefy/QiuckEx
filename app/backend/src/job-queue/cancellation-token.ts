/**
 * Job Queue System - Cancellation Token Implementation
 * 
 * Provides a mechanism for long-running job handlers to check for cancellation requests
 * and terminate gracefully. Cancellation state is stored in memory.
 * 
 * Requirements: 6.3, 6.4, 6.5
 */

import { CancellationToken } from './types/job.types';

/**
 * Error thrown when a job is cancelled
 */
export class JobCancelledError extends Error {
  constructor(jobId: string) {
    super(`Job ${jobId} was cancelled`);
    this.name = 'JobCancelledError';
  }
}

/**
 * Implementation of CancellationToken that checks in-memory cancellation state
 */
export class CancellationTokenImpl implements CancellationToken {
  constructor(
    private readonly jobId: string,
    private readonly cancellationStore: CancellationStore,
  ) {}

  /**
   * Check if cancellation has been requested for this job
   * @returns true if cancellation was requested, false otherwise
   */
  isCancelled(): boolean {
    return this.cancellationStore.isCancelled(this.jobId);
  }

  /**
   * Throw JobCancelledError if cancellation has been requested
   * @throws JobCancelledError if job is cancelled
   */
  throwIfCancelled(): void {
    if (this.isCancelled()) {
      throw new JobCancelledError(this.jobId);
    }
  }
}

/**
 * In-memory store for job cancellation state
 * Manages cancellation flags for all jobs
 */
export class CancellationStore {
  private readonly cancellations = new Map<string, boolean>();

  /**
   * Request cancellation for a job
   * @param jobId - The job ID to cancel
   */
  requestCancellation(jobId: string): void {
    this.cancellations.set(jobId, true);
  }

  /**
   * Check if cancellation has been requested for a job
   * @param jobId - The job ID to check
   * @returns true if cancellation was requested, false otherwise
   */
  isCancelled(jobId: string): boolean {
    return this.cancellations.get(jobId) === true;
  }

  /**
   * Clear cancellation state for a job (cleanup after completion)
   * @param jobId - The job ID to clear
   */
  clearCancellation(jobId: string): void {
    this.cancellations.delete(jobId);
  }

  /**
   * Create a cancellation token for a job
   * @param jobId - The job ID
   * @returns A new CancellationToken instance
   */
  createToken(jobId: string): CancellationToken {
    return new CancellationTokenImpl(jobId, this);
  }

  /**
   * Get the number of active cancellation requests (for testing/monitoring)
   * @returns The count of jobs with cancellation requested
   */
  getActiveCount(): number {
    return this.cancellations.size;
  }
}
