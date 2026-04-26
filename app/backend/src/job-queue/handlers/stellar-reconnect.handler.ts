/**
 * Job Queue System - Stellar Reconnect Handler
 * 
 * Implements the JobHandler interface for Stellar SSE stream reconnection jobs.
 * Reopens SSE streams from the last cursor after disconnection.
 * 
 * Requirements: 11.3, 11.4, 15.4, 15.5
 */

import { Injectable, Logger } from '@nestjs/common';
import { JobHandler, Job, CancellationToken } from '../types';
import { StellarReconnectPayload } from '../types/job-payloads.types';
import { StellarIngestionService } from '../../ingestion/stellar-ingestion.service';
import { PermanentJobError } from './webhook-delivery.handler';

/**
 * Stellar Reconnect Handler
 * 
 * Handles reconnection of Stellar SSE streams after disconnection.
 * This handler is designed to run with unlimited retries (maxAttempts=0)
 * and exponential backoff to ensure eventual reconnection.
 * 
 * The handler delegates to StellarIngestionService which manages the
 * actual SSE stream lifecycle and cursor management.
 */
@Injectable()
export class StellarReconnectHandler implements JobHandler<StellarReconnectPayload> {
  private readonly logger = new Logger(StellarReconnectHandler.name);

  constructor(
    private readonly stellarIngestionService: StellarIngestionService,
  ) {}

  /**
   * Execute SSE stream reconnection
   * 
   * Reopens the SSE stream for the specified contract ID from the last cursor.
   * The StellarIngestionService handles cursor management and will resume
   * event processing from where it left off.
   * 
   * @param job - The reconnection job
   * @param cancellationToken - Token to check for cancellation
   * @throws Error on transient failures (network errors, Horizon unavailable)
   * @throws PermanentJobError on validation failures
   * 
   * **Validates: Requirements 11.3, 11.4**
   */
  async execute(
    job: Job<StellarReconnectPayload>,
    cancellationToken: CancellationToken,
  ): Promise<void> {
    const { contractId, lastCursor } = job.payload;

    this.logger.log(
      `Attempting to reconnect SSE stream (jobId: ${job.id}, ` +
      `contractId: ${contractId}, lastCursor: ${lastCursor})`,
    );

    // Check cancellation before attempting reconnection
    cancellationToken.throwIfCancelled();

    try {
      // Start streaming - this will open a new SSE connection
      // The StellarIngestionService will automatically resume from the last cursor
      // stored in the cursor repository
      await this.stellarIngestionService.startStreaming(contractId);

      this.logger.log(
        `SSE stream reconnected successfully (jobId: ${job.id}, ` +
        `contractId: ${contractId})`,
      );

      // Note: The StellarIngestionService handles:
      // - Loading the last cursor from the cursor repository
      // - Opening the SSE stream with the cursor
      // - Processing events and updating the cursor
      // - Auto-reconnection with exponential backoff on future disconnections
    } catch (error) {
      // Log error with context
      this.logger.error(
        `SSE stream reconnection failed (jobId: ${job.id}, ` +
        `contractId: ${contractId}): ${error.message}`,
        error.stack,
      );

      // Re-throw to trigger job retry with exponential backoff
      // Most reconnection errors are transient (network issues, Horizon unavailable)
      throw error;
    }
  }

  /**
   * Validate reconnection payload
   * 
   * Checks that required fields are present:
   * - contractId: Stellar contract ID to reconnect to (must be non-empty string)
   * - lastCursor: Last cursor position before disconnection (must be non-empty string)
   * 
   * @param payload - The reconnection payload
   * @throws PermanentJobError if validation fails
   * 
   * **Validates: Requirements 11.3, 15.4, 15.5**
   */
  async validate(payload: StellarReconnectPayload): Promise<void> {
    const errors: string[] = [];

    // Validate contractId
    if (!payload.contractId || typeof payload.contractId !== 'string') {
      errors.push('contractId is required and must be a string');
    } else if (payload.contractId.trim().length === 0) {
      errors.push('contractId cannot be empty');
    }

    // Validate lastCursor
    if (!payload.lastCursor || typeof payload.lastCursor !== 'string') {
      errors.push('lastCursor is required and must be a string');
    } else if (payload.lastCursor.trim().length === 0) {
      errors.push('lastCursor cannot be empty');
    }

    if (errors.length > 0) {
      throw new PermanentJobError(`Validation failed: ${errors.join(', ')}`);
    }
  }

  /**
   * Handle reconnection failure
   * 
   * Logs reconnection failure for monitoring and alerting.
   * Since this handler runs with unlimited retries, this method should
   * rarely be called. If it is called, it indicates a persistent issue
   * that requires manual intervention.
   * 
   * @param job - The failed job
   * @param error - The error that caused the failure
   * 
   * **Validates: Requirements 11.4**
   */
  async onFailure(job: Job<StellarReconnectPayload>, error: Error): Promise<void> {
    const { contractId, lastCursor } = job.payload;

    this.logger.error(
      `SSE stream reconnection permanently failed (jobId: ${job.id}, ` +
      `contractId: ${contractId}, lastCursor: ${lastCursor}): ${error.message}`,
      error.stack,
    );

    // Note: This should rarely happen since maxAttempts=0 (unlimited retries).
    // If we reach here, it indicates a persistent issue that requires manual
    // intervention (e.g., invalid contract ID, Horizon endpoint changed, etc.).
    // Operators should monitor reconnection failure metrics and alerts.
  }
}
