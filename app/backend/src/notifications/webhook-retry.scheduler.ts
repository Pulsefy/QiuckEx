import { Injectable, Logger } from "@nestjs/common";
import { Cron, CronExpression } from "@nestjs/schedule";

import { NotificationLogRepository } from "./notification-log.repository";
import { NotificationPreferencesRepository } from "./notification-preferences.repository";
import { WebhookProvider } from "./providers/notification-provider.interface";
import type { BaseNotificationPayload } from "./types/notification.types";

/** Retry delays in milliseconds: 1m, 5m, 30m, 2h */
const RETRY_DELAYS_MS = [60_000, 300_000, 1_800_000, 7_200_000];
const MAX_ATTEMPTS = RETRY_DELAYS_MS.length + 1; // 5 total (1 initial + 4 retries)

@Injectable()
export class WebhookRetryScheduler {
  private readonly logger = new Logger(WebhookRetryScheduler.name);
  private readonly provider = new WebhookProvider();

  constructor(
    private readonly logRepo: NotificationLogRepository,
    private readonly prefsRepo: NotificationPreferencesRepository,
  ) {}

  /**
   * Runs every minute to pick up failed webhook deliveries that are due for retry.
   * After MAX_ATTEMPTS the entry stays in "failed" status (DLQ — inspectable via logs API).
   */
  @Cron(CronExpression.EVERY_MINUTE)
  async retryFailedWebhooks(): Promise<void> {
    const pending = await this.logRepo.getPendingRetries(MAX_ATTEMPTS);
    const webhookPending = pending.filter((r) => r.channel === "webhook");

    if (webhookPending.length === 0) return;

    this.logger.debug(`Retrying ${webhookPending.length} failed webhook(s)`);

    for (const entry of webhookPending) {
      const delayMs = RETRY_DELAYS_MS[entry.attempts - 1] ?? RETRY_DELAYS_MS[RETRY_DELAYS_MS.length - 1];
      const nextRetryAt = new Date(
        new Date(entry.lastFailedAt ?? Date.now()).getTime() + delayMs,
      );

      if (nextRetryAt > new Date()) continue; // not yet due

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

    // Reconstruct a minimal payload from the log entry for redelivery
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

        if (currentAttempts + 1 >= MAX_ATTEMPTS) {
          this.logger.warn(
            `Webhook DLQ: ${eventType}/${eventId} exhausted ${MAX_ATTEMPTS} attempts. Last error: ${message}`,
          );
        } else {
          this.logger.debug(
            `Webhook retry failed (attempt ${currentAttempts + 1}/${MAX_ATTEMPTS}): ${message}`,
          );
        }
      }
    }

    return anySuccess;
  }
}
