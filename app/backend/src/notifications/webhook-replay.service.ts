import {
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
} from "@nestjs/common";

import { AuditService } from "../audit/audit.service";
import { NotificationLogRepository } from "./notification-log.repository";
import { WebhookReplayLimiter } from "./webhook-replay-limiter";
import { WebhookReplayRepository } from "./webhook-replay.repository";
import { WebhookRetryScheduler } from "./webhook-retry.scheduler";
import {
  WEBHOOK_MAX_DELIVERY_ATTEMPTS,
  computeWebhookNextRetryAt,
} from "./webhook-retry.constants";
import type { WebhookDeliveryStatusDto } from "./dto/webhook.dto";
import type { NotificationEventType } from "./types/notification.types";

export interface WebhookReplayResult {
  queued: boolean;
  message: string;
  replayId?: string;
  deliverySuccess?: boolean;
}

@Injectable()
export class WebhookReplayService {
  private readonly logger = new Logger(WebhookReplayService.name);
  private readonly limiter: WebhookReplayLimiter;

  constructor(
    private readonly logRepo: NotificationLogRepository,
    private readonly replayRepo: WebhookReplayRepository,
    private readonly retryScheduler: WebhookRetryScheduler,
    private readonly auditService: AuditService,
  ) {
    const eventCooldownMs = Number(
      process.env["WEBHOOK_REPLAY_EVENT_COOLDOWN_MS"] ?? 30_000,
    );
    const quotaPerHour = Number(
      process.env["WEBHOOK_REPLAY_QUOTA_PER_HOUR"] ?? 20,
    );
    const quotaWindowMs = Number(
      process.env["WEBHOOK_REPLAY_QUOTA_WINDOW_MS"] ?? 3_600_000,
    );

    this.limiter = new WebhookReplayLimiter(
      eventCooldownMs,
      quotaPerHour,
      quotaWindowMs,
    );
  }

  async getDeliveryStatus(
    publicKey: string,
    eventId: string,
    eventType: string,
  ): Promise<WebhookDeliveryStatusDto> {
    const delivery = await this.logRepo.getWebhookDelivery(
      publicKey,
      eventType,
      eventId,
    );

    if (!delivery) {
      throw new NotFoundException({
        message: "No delivery record found for this event",
        code: "WEBHOOK_DELIVERY_NOT_FOUND",
      });
    }

    const replayStats = await this.replayRepo.getReplayStats(
      publicKey,
      eventType,
      eventId,
    );

    const isDlq =
      delivery.status === "dlq" ||
      (delivery.status === "failed" &&
        delivery.attempts >= WEBHOOK_MAX_DELIVERY_ATTEMPTS);

    const nextRetryAt =
      delivery.status === "failed" && !isDlq && delivery.updatedAt
        ? computeWebhookNextRetryAt(delivery.attempts, delivery.updatedAt)
        : null;

    return {
      eventId: delivery.eventId,
      eventType: delivery.eventType,
      status: isDlq ? "dlq" : delivery.status,
      attempts: delivery.attempts,
      maxAttempts: WEBHOOK_MAX_DELIVERY_ATTEMPTS,
      lastError: delivery.lastError,
      dlqReason: isDlq ? delivery.lastError : undefined,
      nextRetryAt: nextRetryAt?.toISOString() ?? undefined,
      httpStatus: delivery.httpStatus,
      responseBody: delivery.responseBody,
      createdAt: delivery.createdAt,
      updatedAt: delivery.updatedAt,
      deliveredAt: delivery.deliveredAt,
      replayCount: replayStats.replayCount,
      lastReplayAt: replayStats.lastReplayAt,
    };
  }

  async listReplayHistory(webhookId: string, limit?: number) {
    const logs = await this.replayRepo.listReplayLogs(webhookId, limit);
    return logs.map((log) => ({
      id: log.id,
      eventType: log.eventType,
      eventId: log.eventId,
      status: log.status,
      reason: log.reason,
      triggeredBy: log.triggeredBy,
      deliverySuccess: log.deliverySuccess,
      createdAt: log.createdAt,
    }));
  }

  /**
   * Safely replay a webhook delivery by event id.
   * Enforces per-event cooldown, per-webhook quota, and audit logging.
   */
  async replayDelivery(
    publicKey: string,
    webhookId: string,
    eventId: string,
    eventType: string,
    triggeredBy = "api",
  ): Promise<WebhookReplayResult> {
    const delivery = await this.logRepo.getWebhookDelivery(
      publicKey,
      eventType,
      eventId,
    );

    if (!delivery) {
      throw new NotFoundException({
        message: "No delivery record found for this event",
        code: "WEBHOOK_DELIVERY_NOT_FOUND",
      });
    }

    if (delivery.status === "pending") {
      const replayLog = await this.replayRepo.createReplayLog({
        webhookId,
        publicKey,
        eventType,
        eventId,
        status: "rejected",
        reason: "Delivery already in progress",
        triggeredBy,
      });

      throw new HttpException(
        {
          message: "Delivery is already in progress for this event",
          code: "WEBHOOK_REPLAY_IN_PROGRESS",
          replayId: replayLog?.id,
        },
        HttpStatus.CONFLICT,
      );
    }

    const limitReason = this.limiter.checkAndRecord(
      webhookId,
      eventType,
      eventId,
    );

    if (limitReason) {
      const replayLog = await this.replayRepo.createReplayLog({
        webhookId,
        publicKey,
        eventType,
        eventId,
        status: "rejected",
        reason: limitReason,
        triggeredBy,
      });

      const code = limitReason.includes("cooldown")
        ? "WEBHOOK_REPLAY_COOLDOWN"
        : "WEBHOOK_REPLAY_QUOTA_EXCEEDED";

      throw new HttpException(
        {
          message: limitReason,
          code,
          replayId: replayLog?.id,
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const replayLog = await this.replayRepo.createReplayLog({
      webhookId,
      publicKey,
      eventType,
      eventId,
      status: "queued",
      triggeredBy,
    });

    await this.auditService.log(
      triggeredBy,
      "webhook.replay",
      `${eventType}/${eventId}`,
      { webhookId, publicKey, replayId: replayLog?.id },
    );

    await this.logRepo.resetForManualReplay(
      publicKey,
      eventType as NotificationEventType,
      eventId,
    );

    const deliverySuccess = await this.retryScheduler.redeliver(
      publicKey,
      eventId,
      eventType,
    );

    if (replayLog) {
      await this.replayRepo.updateReplayLog(replayLog.id, {
        status: deliverySuccess ? "succeeded" : "failed",
        deliverySuccess,
        reason: deliverySuccess
          ? undefined
          : "Redelivery attempt did not succeed — check delivery logs",
      });
    }

    this.logger.log(
      `Webhook replay ${deliverySuccess ? "succeeded" : "failed"}: ${eventType}/${eventId} webhook=${webhookId}`,
    );

    return {
      queued: true,
      deliverySuccess,
      replayId: replayLog?.id,
      message: deliverySuccess
        ? "Event redelivery triggered successfully"
        : "Redelivery attempted but delivery did not succeed — check delivery status",
    };
  }

  /** Exposed for unit tests. */
  resetLimiter(): void {
    this.limiter.reset();
  }
}
