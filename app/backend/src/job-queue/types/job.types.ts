/**
 * Job Queue System - Core Type Definitions
 * 
 * This module defines the core interfaces and enums for the unified job queue system.
 * All background processing jobs (webhooks, payments, exports, etc.) use these types.
 */

/**
 * Job type enum - defines all supported background job types
 */
export enum JobType {
  WEBHOOK_DELIVERY = 'webhook_delivery',
  RECURRING_PAYMENT = 'recurring_payment',
  EXPORT_GENERATION = 'export_generation',
  RECONCILIATION = 'reconciliation',
  STELLAR_RECONNECT = 'stellar_reconnect',
}

/**
 * Job status enum - defines all possible job states
 */
export enum JobStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
}

/**
 * Job entity - represents a background job in the system
 * Stored in the database and managed by the job queue
 */
export interface Job<TPayload = unknown> {
  /** Unique job identifier (UUID) */
  id: string;
  
  /** Type of job (determines which handler processes it) */
  type: JobType;
  
  /** Job-specific payload data */
  payload: TPayload;
  
  /** Current job status */
  status: JobStatus;
  
  /** Number of execution attempts so far */
  attempts: number;
  
  /** Maximum allowed attempts before moving to DLQ */
  maxAttempts: number;
  
  /** When the job was created */
  createdAt: Date;
  
  /** When the job should be executed */
  scheduledAt: Date;
  
  /** When the job started executing (null if not started) */
  startedAt: Date | null;
  
  /** When the job completed (null if not completed) */
  completedAt: Date | null;
  
  /** Error message if job failed (null if no failure) */
  failureReason: string | null;
  
  /** Lock expiry timestamp - prevents concurrent execution */
  visibilityTimeout: Date | null;
}

/**
 * Retry policy configuration - defines retry behavior for a job type
 */
export interface RetryPolicy {
  /** Maximum retry attempts (0 = unlimited) */
  maxAttempts: number;
  
  /** Backoff strategy for calculating retry delays */
  backoffStrategy: 'fixed' | 'linear' | 'exponential';
  
  /** Initial delay in milliseconds before first retry */
  initialDelayMs: number;
  
  /** Maximum delay in milliseconds (caps exponential growth) */
  maxDelayMs: number;
  
  /** How long a job stays locked when running (milliseconds) */
  visibilityTimeoutMs: number;
}

/**
 * Cancellation token - allows handlers to check for cancellation requests
 */
export interface CancellationToken {
  /** Check if cancellation has been requested */
  isCancelled(): boolean;
  
  /** Throw error if cancellation has been requested */
  throwIfCancelled(): void;
}

/**
 * Job handler interface - implemented by each job type handler
 */
export interface JobHandler<TPayload = unknown> {
  /**
   * Execute the job with the given payload
   * @param job - The job to execute
   * @param cancellationToken - Token to check for cancellation
   * @throws Error on transient failures (will retry)
   * @throws PermanentJobError on permanent failures (no retry)
   */
  execute(job: Job<TPayload>, cancellationToken: CancellationToken): Promise<void>;
  
  /**
   * Validate the job payload before execution
   * @param payload - The payload to validate
   * @throws ValidationError if payload is invalid
   */
  validate(payload: TPayload): Promise<void>;
  
  /**
   * Handle job failure (logging, cleanup, etc.)
   * @param job - The failed job
   * @param error - The error that caused the failure
   */
  onFailure(job: Job<TPayload>, error: Error): Promise<void>;
}
