/**
 * Job Queue System - Recurring Payment Handler
 * 
 * Implements the JobHandler interface for recurring payment jobs.
 * Submits Stellar transactions for scheduled recurring payments.
 * 
 * Requirements: 8.3, 8.4, 8.5, 15.4, 15.5
 */

import { Injectable, Logger } from '@nestjs/common';
import { JobHandler, Job, CancellationToken } from '../types';
import { RecurringPaymentPayload } from '../types/job-payloads.types';
import { RecurringPaymentProcessor } from '../../stellar/recurring-payment-processor';
import { RecurringPaymentsRepository } from '../../links/recurring-payments.repository';
import { ExecutionStatus } from '../../links/dto/recurring-payment.dto';
import { PermanentJobError } from './webhook-delivery.handler';

/**
 * Recurring Payment Handler
 * 
 * Submits Stellar transactions for recurring payments.
 * Classifies Stellar errors as transient (tx_bad_seq, tx_insufficient_fee) or permanent (tx_bad_auth, tx_malformed).
 * Marks execution records as failed when job exhausts retries.
 */
@Injectable()
export class RecurringPaymentHandler implements JobHandler<RecurringPaymentPayload> {
  private readonly logger = new Logger(RecurringPaymentHandler.name);

  constructor(
    private readonly paymentProcessor: RecurringPaymentProcessor,
    private readonly recurringPaymentsRepo: RecurringPaymentsRepository,
  ) {}

  /**
   * Execute recurring payment
   * 
   * Submits a Stellar transaction for the recurring payment.
   * Checks cancellation token before transaction submission.
   * 
   * @param job - The recurring payment job
   * @param cancellationToken - Token to check for cancellation
   * @throws PermanentJobError for permanent Stellar errors (tx_bad_auth, tx_malformed, etc.)
   * @throws Error for transient Stellar errors (tx_bad_seq, tx_insufficient_fee)
   * 
   * **Validates: Requirements 8.3, 8.4, 8.5**
   */
  async execute(job: Job<RecurringPaymentPayload>, cancellationToken: CancellationToken): Promise<void> {
    // Check cancellation token before transaction submission
    cancellationToken.throwIfCancelled();

    const { recurringLinkId, executionId, recipientAddress, amount, asset, assetIssuer, memo, memoType } = job.payload;

    this.logger.log(
      `Executing recurring payment: ${amount} ${asset} to ${recipientAddress} (linkId: ${recurringLinkId}, executionId: ${executionId}, jobId: ${job.id})`,
    );

    try {
      // Submit Stellar transaction
      const transactionHash = await this.paymentProcessor.submitRecurringPayment({
        recipientAddress,
        amount: parseFloat(amount),
        assetCode: asset,
        assetIssuer,
        memo,
        memoType,
        referenceId: recurringLinkId,
      });

      // Update execution record with success
      await this.recurringPaymentsRepo.updateExecutionStatus(
        executionId,
        ExecutionStatus.SUCCESS,
        {
          executedAt: new Date(),
          transactionHash,
        },
      );

      // Increment executed count on the recurring link
      await this.recurringPaymentsRepo.incrementExecutedCount(recurringLinkId);

      this.logger.log(
        `Recurring payment executed successfully (txHash: ${transactionHash}, executionId: ${executionId}, jobId: ${job.id})`,
      );
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      this.logger.error(
        `Recurring payment failed (executionId: ${executionId}, jobId: ${job.id}): ${errorMessage}`,
        error instanceof Error ? error.stack : undefined,
      );

      // Classify Stellar errors
      if (this.isPermanentStellarError(error)) {
        this.logger.error(
          `Permanent Stellar error detected (executionId: ${executionId}, jobId: ${job.id}) - no retry`,
        );
        throw new PermanentJobError(`Permanent Stellar error: ${errorMessage}`);
      }

      // Transient error - will retry
      this.logger.warn(
        `Transient Stellar error detected (executionId: ${executionId}, jobId: ${job.id}) - will retry`,
      );
      throw new Error(`Transient Stellar error: ${errorMessage}`);
    }
  }

  /**
   * Validate recurring payment payload
   * 
   * Checks that required fields are present:
   * - recurringLinkId: ID of the recurring link configuration
   * - recipientAddress: Stellar address to send payment to
   * - amount: Payment amount
   * - asset: Asset code (e.g., 'XLM', 'USDC')
   * 
   * @param payload - The recurring payment payload
   * @throws PermanentJobError if validation fails
   * 
   * **Validates: Requirements 8.4, 15.4, 15.5**
   */
  async validate(payload: RecurringPaymentPayload): Promise<void> {
    const errors: string[] = [];

    if (!payload.recurringLinkId || typeof payload.recurringLinkId !== 'string') {
      errors.push('recurringLinkId is required and must be a string');
    }

    if (!payload.executionId || typeof payload.executionId !== 'string') {
      errors.push('executionId is required and must be a string');
    }

    if (!payload.recipientAddress || typeof payload.recipientAddress !== 'string') {
      errors.push('recipientAddress is required and must be a string');
    }

    if (!payload.amount || typeof payload.amount !== 'string') {
      errors.push('amount is required and must be a string');
    }

    if (!payload.asset || typeof payload.asset !== 'string') {
      errors.push('asset is required and must be a string');
    }

    // Validate amount is a valid number
    if (payload.amount) {
      const amountNum = parseFloat(payload.amount);
      if (isNaN(amountNum) || amountNum <= 0) {
        errors.push('amount must be a positive number');
      }
    }

    // Validate Stellar address format (basic check)
    if (payload.recipientAddress && !this.isValidStellarAddress(payload.recipientAddress)) {
      errors.push('recipientAddress must be a valid Stellar address');
    }

    if (errors.length > 0) {
      throw new PermanentJobError(`Validation failed: ${errors.join(', ')}`);
    }
  }

  /**
   * Handle job failure
   * 
   * Marks the execution record as permanently failed when the job exhausts all retry attempts.
   * This is called when the job moves to the Dead Letter Queue.
   * 
   * @param job - The failed job
   * @param error - The error that caused the failure
   * 
   * **Validates: Requirements 8.5**
   */
  async onFailure(job: Job<RecurringPaymentPayload>, error: Error): Promise<void> {
    const { recurringLinkId, executionId } = job.payload;

    this.logger.error(
      `Recurring payment permanently failed (linkId: ${recurringLinkId}, executionId: ${executionId}, jobId: ${job.id}): ${error.message}`,
    );

    // Mark execution record as permanently failed
    try {
      await this.recurringPaymentsRepo.updateExecutionStatus(
        executionId,
        ExecutionStatus.FAILED,
        {
          failureReason: error.message,
          lastRetryAt: new Date(),
        },
      );
    } catch (updateError) {
      this.logger.error(
        `Failed to update execution status to failed (executionId: ${executionId}, jobId: ${job.id}): ${updateError instanceof Error ? updateError.message : 'Unknown error'}`,
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Private Helper Methods
  // ---------------------------------------------------------------------------

  /**
   * Check if a Stellar error is permanent (no retry)
   * 
   * Permanent errors:
   * - tx_bad_auth: Invalid signature or authorization
   * - tx_malformed: Malformed transaction
   * - tx_bad_auth_extra: Extra unauthorized signatures
   * - tx_insufficient_balance: Insufficient balance (permanent for this attempt)
   * - op_no_destination: Destination account doesn't exist
   * - op_malformed: Malformed operation
   * - op_underfunded: Source account underfunded
   * 
   * Transient errors:
   * - tx_bad_seq: Bad sequence number (can retry with updated sequence)
   * - tx_insufficient_fee: Fee too low (can retry with higher fee)
   * - tx_too_late: Transaction expired (can retry with new timebounds)
   * - tx_too_early: Transaction not yet valid (can retry later)
   * - Network errors, timeouts, etc.
   */
  private isPermanentStellarError(error: unknown): boolean {
    if (!(error instanceof Error)) {
      return false;
    }

    const errorMessage = error.message.toLowerCase();

    // Check for permanent Stellar error codes
    const permanentErrorCodes = [
      'tx_bad_auth',
      'tx_malformed',
      'tx_bad_auth_extra',
      'tx_insufficient_balance',
      'op_no_destination',
      'op_malformed',
      'op_underfunded',
      'op_line_full',
      'op_no_trust',
      'op_not_authorized',
    ];

    for (const code of permanentErrorCodes) {
      if (errorMessage.includes(code)) {
        return true;
      }
    }

    // Check for transient Stellar error codes (explicitly not permanent)
    const transientErrorCodes = [
      'tx_bad_seq',
      'tx_insufficient_fee',
      'tx_too_late',
      'tx_too_early',
    ];

    for (const code of transientErrorCodes) {
      if (errorMessage.includes(code)) {
        return false;
      }
    }

    // Network errors are transient
    if (
      errorMessage.includes('network') ||
      errorMessage.includes('timeout') ||
      errorMessage.includes('econnrefused') ||
      errorMessage.includes('enotfound')
    ) {
      return false;
    }

    // Default to transient for unknown errors (safer to retry)
    return false;
  }

  /**
   * Validate Stellar address format
   * 
   * Basic validation: must start with 'G' and be 56 characters long
   */
  private isValidStellarAddress(address: string): boolean {
    return address.length === 56 && address.startsWith('G');
  }
}
