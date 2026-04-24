import { Injectable, Logger } from "@nestjs/common";
import * as crypto from "crypto";

import { NotificationPreferencesRepository } from "./notification-preferences.repository";
import { NotificationLogRepository } from "./notification-log.repository";
import { WebhookRetryScheduler } from "./webhook-retry.scheduler";
import type { NotificationPreference } from "./types/notification.types";
import type {
  CreateWebhookDto,
  UpdateWebhookDto,
  WebhookResponseDto,
  WebhookDeliveryLogDto,
  WebhookStatsDto,
} from "./dto/webhook.dto";

@Injectable()
export class WebhookService {
  private readonly logger = new Logger(WebhookService.name);

  constructor(
    private readonly prefsRepo: NotificationPreferencesRepository,
    private readonly logRepo: NotificationLogRepository,
    private readonly retryScheduler: WebhookRetryScheduler,
  ) {}

  async createWebhook(
    publicKey: string,
    dto: CreateWebhookDto,
  ): Promise<WebhookResponseDto> {
    const secret = dto.secret ?? this.generateSecret();

    const preference = await this.prefsRepo.upsertPreference(
      publicKey,
      "webhook",
      {
        webhookUrl: dto.webhookUrl,
        webhookSecret: secret,
        events: dto.events ?? null,
        minAmountStroops: dto.minAmountStroops
          ? BigInt(dto.minAmountStroops)
          : 0n,
        enabled: true,
      },
    );

    return this.toResponse(preference);
  }

  async listWebhooks(publicKey: string): Promise<WebhookResponseDto[]> {
    const preferences = await this.prefsRepo.getWebhooksByPublicKey(publicKey);
    return preferences.map((p) => this.toResponse(p));
  }

  async getWebhook(id: string): Promise<WebhookResponseDto | null> {
    const preference = await this.prefsRepo.getWebhookById(id);
    if (!preference) return null;
    return this.toResponse(preference);
  }

  async updateWebhook(
    id: string,
    publicKey: string,
    dto: UpdateWebhookDto,
  ): Promise<WebhookResponseDto | null> {
    const existing = await this.prefsRepo.getWebhookById(id);
    if (!existing || existing.publicKey !== publicKey) {
      return null;
    }

    const updated = await this.prefsRepo.upsertPreference(
      publicKey,
      "webhook",
      {
        webhookUrl: dto.webhookUrl ?? existing.webhookUrl,
        webhookSecret: existing.webhookSecret,
        events: dto.events ?? existing.events,
        minAmountStroops:
          dto.minAmountStroops !== undefined
            ? BigInt(dto.minAmountStroops)
            : existing.minAmountStroops,
        enabled: dto.enabled ?? existing.enabled,
      },
    );

    return this.toResponse(updated);
  }

  async deleteWebhook(id: string, publicKey: string): Promise<boolean> {
    const existing = await this.prefsRepo.getWebhookById(id);
    if (!existing || existing.publicKey !== publicKey) {
      return false;
    }

    await this.prefsRepo.deleteWebhook(id);
    return true;
  }

  async regenerateSecret(
    id: string,
    publicKey: string,
  ): Promise<{ secret: string } | null> {
    const existing = await this.prefsRepo.getWebhookById(id);
    if (!existing || existing.publicKey !== publicKey) {
      return null;
    }

    const newSecret = this.generateSecret();
    await this.prefsRepo.regenerateWebhookSecret(id, newSecret);

    return { secret: newSecret };
  }

  async getDeliveryLogs(
    publicKey: string,
    limit?: number,
  ): Promise<WebhookDeliveryLogDto[]> {
    const logs = await this.logRepo.getWebhookDeliveryLogs(publicKey, limit);
    return logs.map((log) => ({
      id: log.id,
      eventType: log.eventType,
      eventId: log.eventId,
      status: log.status,
      attempts: log.attempts,
      lastError: log.lastError,
      httpStatus: log.httpStatus,
      responseBody: log.responseBody,
      createdAt: log.createdAt,
      deliveredAt: log.deliveredAt,
    }));
  }

  async getStats(publicKey: string): Promise<WebhookStatsDto> {
    const stats = await this.logRepo.getWebhookStats(publicKey);
    return {
      totalSent: stats.totalSent,
      totalFailed: stats.totalFailed,
      pendingRetries: stats.pendingRetries,
      lastDeliveryAt: stats.lastDeliveryAt,
      lastError: stats.lastError,
    };
  }

  /**
   * Trigger immediate redelivery of a specific event via the retry scheduler.
   * Returns true if at least one webhook delivery succeeded.
   */
  async redeliverEvent(
    publicKey: string,
    eventId: string,
    eventType: string,
  ): Promise<boolean> {
    return this.retryScheduler.redeliver(publicKey, eventId, eventType);
  }

  private generateSecret(): string {
    const bytes = crypto.randomBytes(32);
    return `whsec_${bytes.toString("hex")}`;
  }

  private toResponse(preference: NotificationPreference): WebhookResponseDto {
    return {
      id: preference.id,
      publicKey: preference.publicKey,
      webhookUrl: preference.webhookUrl ?? "",
      secret: preference.webhookSecret ?? "",
      events: preference.events,
      minAmountStroops: preference.minAmountStroops.toString(),
      enabled: preference.enabled,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }
}
