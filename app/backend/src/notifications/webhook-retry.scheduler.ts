import { Injectable, Logger } from "@nestjs/common";
import { Cron, CronExpression } from "@nestjs/schedule";

import { MetricsService } from "../metrics/metrics.service";
import { NotificationLogRepository } from "./notification-log.repository";
import { NotificationPreferencesRepository } from "./notification-preferences.repository";
import { WebhookProvider } from "./providers/notification-provider.interface";
import type { BaseNotificationPayload } from "./types/notification.types";
import {
  WEBHOOK_MAX_DELIVERY_ATTEMPTS,
  WEBHOOK_RETRY_DELAYS_MS,
} from "./webhook-retry.constants";

@Injectable()
export class WebhookRetryScheduler {
  private readonly logger = new Logger(WebhookRetryScheduler.name);
  private readonly provider = new WebhookProvider();

  constructor(
    private readonly logRepo: NotificationLogRepository,
    private readonly prefsRepo: NotificationPreferencesRepository,
    private readonly metrics?: MetricsService,
  ) {}

  /**
   * Runs every minute to pick up failed webhook deliveries that are due for retry.
   * After MAX_ATTEMPTS the entry moves to DLQ status (inspectable via delivery API).
   */
  @Cron(CronExpression.EVERY_MINUTE)
  async retryFailedWebhooks(): Promise<void> {
    const pending = await this.logRepo.getPendingRetries(
      WEBHOOK_MAX_DELIVERY_ATTEMPTS,
    );
    const webhookPending = pending.filter((r) => r.channel === "webhook");

    await this.recordDeliveryMetrics(webhookPending.map((r) => r.publicKey));

    if (webhookPending.length === 0) return;

    this.logger.debug(`Retrying ${webhookPending.length} failed webhook(s)`);

    for (const entry of webhookPending) {
      const delayMs =
        WEBHOOK_RETRY_DELAYS_MS[entry.attempts - 1] ??
        WEBHOOK_RETRY_DELAYS_MS[WEBHOOK_RETRY_DELAYS_MS.length - 1];
      const nextRetryAt = new Date(
        new Date(entry.lastFailedAt ?? Date.now()).getTime() + delayMs,
      );

      if (nextRetryAt > new Date()) continue;

      await this.attemptRedelivery(
        entry.publicKey,
        entry.eventType,
        entry.eventId,
        entry.attempts,
      );
    }
  }

  /**
   * Manually redeliver a specific event (admin / consumer-triggered).
   * Returns true if delivery succeeded.
   */
  async redeliver(
    publicKey: string,
    eventId: string,
    eventType: string,
  ): Promise<boolean> {
    return this.attemptRedelivery(publicKey, eventType as never, eventId, 0);
  }

  private async attemptRedelivery(
    publicKey: string,
    eventType: string,
    eventId: string,
    currentAttempts: number,
  ): Promise<boolean> {
    const webhooks = await this.prefsRepo.getWebhooksByPublicKey(publicKey);
    const active = webhooks.filter((w) => w.enabled && w.webhookUrl);

    if (active.length === 0) {
      this.logger.warn(
        `No active webhooks for ${publicKey.slice(0, 8)}... — skipping retry`,
      );
      return false;
    }

    const payload: BaseNotificationPayload = {
      eventType: eventType as never,
      eventId,
      recipientPublicKey: publicKey,
      title: `Redelivery: ${eventType}`,
      body: `Event ${eventId} redelivered`,
      occurredAt: new Date().toISOString(),
    };

    let anySuccess = false;

    for (const pref of active) {
      try {
        const result = await this.provider.send(pref, payload);
        await this.logRepo.markSent(
          publicKey,
          "webhook",
          eventType as never,
          eventId,
          result.messageId,
          result.httpStatus,
          result.responseBody,
        );
        this.logger.log(
          `Webhook redelivered: ${eventType}/${eventId} -> ${pref.webhookUrl} (attempt ${currentAttempts + 1})`,
        );
        anySuccess = true;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        await this.logRepo.markFailed(
          publicKey,
          "webhook",
          eventType as never,
          eventId,
          message,
        );

        if (currentAttempts + 1 >= WEBHOOK_MAX_DELIVERY_ATTEMPTS) {
          this.logger.warn(
            `Webhook DLQ: ${eventType}/${eventId} exhausted ${WEBHOOK_MAX_DELIVERY_ATTEMPTS} attempts. Last error: ${message}`,
          );
        } else {
          this.logger.debug(
            `Webhook retry failed (attempt ${currentAttempts + 1}/${WEBHOOK_MAX_DELIVERY_ATTEMPTS}): ${message}`,
          );
        }
      }
    }

    return anySuccess;
  }

  /**
   * Publish delivery health gauges per affected public key:
   * webhook_delivery_success_rate (0-1) and webhook_dlq_size.
   */
  private async recordDeliveryMetrics(publicKeys: string[]): Promise<void> {
    if (!this.metrics) return;

    const keys = [...new Set(publicKeys)];
    if (keys.length === 0) return;

    for (const publicKey of keys) {
      try {
        const { sent, failed, dlq } =
          await this.logRepo.getWebhookDeliveryTotals(publicKey);
        const total = sent + failed;
        const rate = total > 0 ? sent / total : 0;
        this.metrics.setWebhookDeliverySuccessRate(publicKey, rate);
        this.metrics.setWebhookDlqSize(publicKey, dlq);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        this.logger.debug(
          `Failed to record webhook delivery metrics for ${publicKey.slice(0, 8)}...: ${message}`,
        );
      }
    }
  }
}
