/**
 * Job Queue System - Webhook Delivery Handler
 * 
 * Implements the JobHandler interface for webhook delivery jobs.
 * Sends HTTP POST requests to webhook URLs and handles retries based on response codes.
 * 
 * Requirements: 7.3, 7.4, 7.5, 15.4, 15.5
 */

import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { JobHandler, Job, CancellationToken } from '../types';
import { WebhookDeliveryPayload } from '../types/job-payloads.types';
import { NotificationLogRepository } from '../../notifications/notification-log.repository';
import { NotificationEventType } from '../../notifications/types/notification.types';
import type { BaseNotificationPayload, NotificationPreference } from '../../notifications/types/notification.types';
import { INotificationProvider, NOTIFICATION_PROVIDERS, WebhookProvider } from '../../notifications/providers/notification-provider.interface';

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
    @Inject(NOTIFICATION_PROVIDERS)
    @Optional() private readonly notificationProviders?: INotificationProvider[],
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

    const { webhookUrl, eventType, eventId, payload, recipientPublicKey, correlationId, webhookSecret } = job.payload;

    this.logger.log(
      `Delivering webhook to ${webhookUrl} (eventType: ${eventType}, eventId: ${eventId}, jobId: ${job.id}, correlationId: ${correlationId ?? 'N/A'})`,
    );

    try {
      const provider = (this.notificationProviders ?? [new WebhookProvider()]).find(
        (candidate) => candidate.channel === 'webhook',
      );
      if (!provider) throw new Error('Webhook provider is not configured');

      const preference: NotificationPreference = {
        id: `job-${job.id}`,
        publicKey: recipientPublicKey,
        channel: 'webhook',
        webhookUrl,
        webhookSecret,
        events: null,
        minAmountStroops: 0n,
        enabled: true,
      };
      const result = await provider.send(preference, {
        eventType: eventType as NotificationEventType,
        eventId,
        recipientPublicKey,
        title: String(payload.title ?? eventType),
        body: String(payload.body ?? ''),
        occurredAt: String(payload.occurredAt ?? new Date().toISOString()),
        metadata: payload.metadata,
        correlationId,
      } as BaseNotificationPayload);

      await this.notificationLogRepo.markSent(
        recipientPublicKey,
        'webhook',
        eventType as NotificationEventType,
        eventId,
        result.messageId,
        result.httpStatus,
        result.responseBody,
      );

      this.logger.log(
        `Webhook delivered successfully to ${webhookUrl} (status: ${result.httpStatus}, jobId: ${job.id})`,
      );
      return;
    } catch (error) {
      // Re-throw PermanentJobError as-is
      if (error instanceof PermanentJobError) {
        throw error;
      }

      const status = error instanceof Error
        ? Number(error.message.match(/HTTP (\d{3})/)?.[1])
        : NaN;
      if (status >= 400 && status < 500 && status !== 408 && status !== 429) {
        throw new PermanentJobError(error instanceof Error ? error.message : String(error));
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
        eventType as NotificationEventType, // eventType from payload may not match NotificationEventType enum
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
