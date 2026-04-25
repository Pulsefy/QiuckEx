/**
 * Job Queue System - Webhook Delivery Handler
 * 
 * Implements the JobHandler interface for webhook delivery jobs.
 * Sends HTTP POST requests to webhook URLs and handles retries based on response codes.
 * 
 * Requirements: 7.3, 7.4, 7.5, 15.4, 15.5
 */

import { Injectable, Logger } from '@nestjs/common';
import { JobHandler, Job, CancellationToken } from '../types';
import { WebhookDeliveryPayload } from '../types/job-payloads.types';
import { NotificationLogRepository } from '../../notifications/notification-log.repository';

/**
 * Error thrown for permanent job failures (no retry)
 * Used for 4xx errors (except 408, 429) and validation failures
 */
export class PermanentJobError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PermanentJobError';
  }
}

/**
 * Webhook Delivery Handler
 * 
 * Sends HTTP POST requests to webhook URLs with event payloads.
 * Classifies errors as transient (5xx, network) or permanent (4xx, validation).
 * Logs failures to notification_logs table for audit trail.
 */
@Injectable()
export class WebhookDeliveryHandler implements JobHandler<WebhookDeliveryPayload> {
  private readonly logger = new Logger(WebhookDeliveryHandler.name);
  private readonly maxResponseBodyLength = 1000;
  private readonly requestTimeoutMs = 30000; // 30 seconds

  constructor(
    private readonly notificationLogRepo: NotificationLogRepository,
  ) {}

  /**
   * Execute webhook delivery
   * 
   * Sends HTTP POST request to the webhook URL with the event payload.
   * Checks cancellation token before making the request.
   * 
   * @param job - The webhook delivery job
   * @param cancellationToken - Token to check for cancellation
   * @throws PermanentJobError for 4xx responses (except 408, 429)
   * @throws Error for 5xx responses and network errors (transient)
   * 
   * **Validates: Requirements 7.3, 7.4, 7.5**
   */
  async execute(job: Job<WebhookDeliveryPayload>, cancellationToken: CancellationToken): Promise<void> {
    // Check cancellation token before HTTP request
    cancellationToken.throwIfCancelled();

    const { webhookUrl, eventType, eventId, payload, recipientPublicKey } = job.payload;

    this.logger.log(
      `Delivering webhook to ${webhookUrl} (eventType: ${eventType}, eventId: ${eventId}, jobId: ${job.id})`,
    );

    try {
      // Create abort controller for request timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.requestTimeoutMs);

      // Send HTTP POST request
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-QuickEx-Event': eventType,
          'X-QuickEx-Event-Id': eventId,
          'User-Agent': 'QuickEx-Webhook/1.0',
        },
        body: JSON.stringify({
          eventType,
          eventId,
          recipientPublicKey,
          payload,
          timestamp: new Date().toISOString(),
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Read response body (truncate if too long)
      let responseBody: string | undefined;
      try {
        const text = await response.text();
        responseBody =
          text.length > this.maxResponseBodyLength
            ? text.slice(0, this.maxResponseBodyLength) + '...'
            : text;
      } catch {
        // Ignore response body read errors
        responseBody = undefined;
      }

      // Check response status
      if (response.status >= 200 && response.status < 300) {
        // Success - log to notification_logs
        await this.notificationLogRepo.markSent(
          recipientPublicKey,
          'webhook',
          eventType as any, // eventType from payload may not match NotificationEventType enum
          eventId,
          undefined, // no provider message ID for webhooks
          response.status,
          responseBody,
        );

        this.logger.log(
          `Webhook delivered successfully to ${webhookUrl} (status: ${response.status}, jobId: ${job.id})`,
        );
        return;
      }

      // Non-2xx response - classify error
      const errorMessage = `Webhook returned HTTP ${response.status} for ${webhookUrl}: ${responseBody ?? 'no response body'}`;

      if (response.status >= 400 && response.status < 500) {
        // 4xx errors are generally permanent, except:
        // - 408 Request Timeout (transient)
        // - 429 Too Many Requests (transient, should retry)
        if (response.status === 408 || response.status === 429) {
          this.logger.warn(
            `Webhook returned transient 4xx error (status: ${response.status}, jobId: ${job.id}) - will retry`,
          );
          throw new Error(errorMessage);
        }

        // Other 4xx errors are permanent (bad request, unauthorized, not found, etc.)
        this.logger.error(
          `Webhook returned permanent 4xx error (status: ${response.status}, jobId: ${job.id}) - no retry`,
        );
        throw new PermanentJobError(errorMessage);
      }

      // 5xx errors are transient (server errors, should retry)
      if (response.status >= 500) {
        this.logger.warn(
          `Webhook returned 5xx error (status: ${response.status}, jobId: ${job.id}) - will retry`,
        );
        throw new Error(errorMessage);
      }

      // Other status codes (3xx, etc.) - treat as transient
      this.logger.warn(
        `Webhook returned unexpected status (status: ${response.status}, jobId: ${job.id}) - will retry`,
      );
      throw new Error(errorMessage);
    } catch (error) {
      // Re-throw PermanentJobError as-is
      if (error instanceof PermanentJobError) {
        throw error;
      }

      // Handle network errors (timeout, connection refused, DNS failure, etc.)
      if (error.name === 'AbortError') {
        const timeoutError = `Webhook request timed out after ${this.requestTimeoutMs}ms for ${webhookUrl}`;
        this.logger.warn(`${timeoutError} (jobId: ${job.id}) - will retry`);
        throw new Error(timeoutError);
      }

      // Other network errors are transient
      const networkError = `Network error delivering webhook to ${webhookUrl}: ${error.message}`;
      this.logger.warn(`${networkError} (jobId: ${job.id}) - will retry`);
      throw new Error(networkError);
    }
  }

  /**
   * Validate webhook delivery payload
   * 
   * Checks that required fields are present:
   * - webhookUrl: Target URL for webhook delivery
   * - eventType: Type of event being delivered
   * 
   * @param payload - The webhook delivery payload
   * @throws PermanentJobError if validation fails
   * 
   * **Validates: Requirements 7.4, 15.4, 15.5**
   */
  async validate(payload: WebhookDeliveryPayload): Promise<void> {
    const errors: string[] = [];

    if (!payload.webhookUrl || typeof payload.webhookUrl !== 'string') {
      errors.push('webhookUrl is required and must be a string');
    }

    if (!payload.eventType || typeof payload.eventType !== 'string') {
      errors.push('eventType is required and must be a string');
    }

    if (!payload.eventId || typeof payload.eventId !== 'string') {
      errors.push('eventId is required and must be a string');
    }

    if (!payload.recipientPublicKey || typeof payload.recipientPublicKey !== 'string') {
      errors.push('recipientPublicKey is required and must be a string');
    }

    if (!payload.payload || typeof payload.payload !== 'object') {
      errors.push('payload is required and must be an object');
    }

    if (errors.length > 0) {
      throw new PermanentJobError(`Validation failed: ${errors.join(', ')}`);
    }

    // Validate URL format
    try {
      new URL(payload.webhookUrl);
    } catch {
      throw new PermanentJobError(`Invalid webhook URL: ${payload.webhookUrl}`);
    }
  }

  /**
   * Handle job failure
   * 
   * Logs webhook delivery failure to notification_logs table for audit trail.
   * This is called when the job exhausts all retry attempts and moves to DLQ.
   * 
   * @param job - The failed job
   * @param error - The error that caused the failure
   * 
   * **Validates: Requirements 7.5**
   */
  async onFailure(job: Job<WebhookDeliveryPayload>, error: Error): Promise<void> {
    const { recipientPublicKey, eventType, eventId } = job.payload;

    this.logger.error(
      `Webhook delivery permanently failed for ${recipientPublicKey} (eventType: ${eventType}, eventId: ${eventId}, jobId: ${job.id}): ${error.message}`,
    );

    // Log failure to notification_logs table
    try {
      await this.notificationLogRepo.markFailed(
        recipientPublicKey,
        'webhook',
        eventType as any, // eventType from payload may not match NotificationEventType enum
        eventId,
        error.message,
      );
    } catch (logError) {
      this.logger.error(
        `Failed to log webhook failure to notification_logs (jobId: ${job.id}): ${logError.message}`,
      );
    }
  }
}
