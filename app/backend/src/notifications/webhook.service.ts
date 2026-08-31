import { Injectable, Logger } from "@nestjs/common";
import * as crypto from "crypto";

import { NotificationPreferencesRepository } from "./notification-preferences.repository";
import { NotificationLogRepository } from "./notification-log.repository";
import { WebhookReplayService } from "./webhook-replay.service";
import type { NotificationPreference } from "./types/notification.types";
import type {
  CreateWebhookDto,
  UpdateWebhookDto,
  WebhookResponseDto,
  WebhookDeliveryLogDto,
  WebhookStatsDto,
  WebhookDeliveryStatusDto,
  WebhookDeliveryAttemptDto,
  WebhookDeliveryAttemptDetailDto,
  WebhookReplayLogDto,
  WebhookRedeliverResponseDto,
} from "./dto/webhook.dto";

@Injectable()
export class WebhookService {
  private readonly logger = new Logger(WebhookService.name);

  constructor(
    private readonly prefsRepo: NotificationPreferencesRepository,
    private readonly logRepo: NotificationLogRepository,
    private readonly replayService: WebhookReplayService,
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

  async listWebhooks(
    publicKey: string,
    cursor?: string,
    limit?: number,
  ): Promise<{ data: WebhookResponseDto[]; next_cursor: string | null; has_more: boolean }> {
    const preferences = await this.prefsRepo.getWebhooksByPublicKeyPaginated(publicKey, cursor, limit);
    return {
      data: preferences.data.map((p) => this.toResponse(p)),
      next_cursor: preferences.next_cursor,
      has_more: preferences.has_more,
    };
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
    cursor?: string,
  ): Promise<{ data: WebhookDeliveryLogDto[]; next_cursor: string | null; has_more: boolean }> {
    const result = await this.logRepo.getWebhookDeliveryLogsPaginated(publicKey, limit, cursor);
    return {
      data: result.data.map((log) => ({
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
      })),
      next_cursor: result.next_cursor,
      has_more: result.has_more,
    };
  }

  async listWebhookDeliveryAttempts(
    publicKey: string,
    filters: {
      endpointId?: string;
      status?: string;
      eventType?: string;
      limit?: number;
      cursor?: string;
    } = {},
  ): Promise<{ data: WebhookDeliveryAttemptDto[]; next_cursor: string | null; has_more: boolean }> {
    const result = await this.logRepo.getWebhookDeliveryAttemptsPaginated(publicKey, {
      endpointId: filters.endpointId,
      status: filters.status,
      eventType: filters.eventType,
      limit: filters.limit,
      cursor: filters.cursor,
    });

    return {
      data: result.data.map((attempt) => ({
        id: attempt.id,
        webhookId: filters.endpointId ?? attempt.webhookId ?? "",
        endpointUrl: attempt.endpointUrl,
        eventType: attempt.eventType,
        eventId: attempt.eventId,
        status: attempt.status,
        attempts: attempt.attempts,
        retryCount: Math.max((attempt.attempts ?? 1) - 1, 0),
        lastError: this.redactString(attempt.lastError),
        httpStatus: attempt.httpStatus,
        responseBody: this.redactString(attempt.responseBody),
        payloadMetadata: this.redactPayloadMetadata({
          eventType: attempt.eventType,
          eventId: attempt.eventId,
          status: attempt.status,
          httpStatus: attempt.httpStatus,
          responseBody: attempt.responseBody,
          lastError: attempt.lastError,
        }),
        createdAt: attempt.createdAt,
        updatedAt: attempt.updatedAt,
        deliveredAt: attempt.deliveredAt,
      })),
      next_cursor: result.next_cursor,
      has_more: result.has_more,
    };
  }

  async getWebhookDeliveryAttempt(
    publicKey: string,
    endpointId: string,
    attemptId: string,
  ): Promise<WebhookDeliveryAttemptDetailDto | null> {
    const attempt = await this.logRepo.getWebhookDeliveryAttempt(publicKey, endpointId, attemptId);
    if (!attempt) return null;

    const payloadMetadata = this.redactPayloadMetadata({
      eventType: attempt.eventType,
      eventId: attempt.eventId,
      status: attempt.status,
      httpStatus: attempt.httpStatus,
      responseBody: attempt.responseBody,
      lastError: attempt.lastError,
    });

    return {
      id: attempt.id,
      webhookId: endpointId,
      endpointUrl: attempt.endpointUrl,
      eventType: attempt.eventType,
      eventId: attempt.eventId,
      status: attempt.status,
      attempts: attempt.attempts,
      retryCount: Math.max((attempt.attempts ?? 1) - 1, 0),
      lastError: this.redactString(attempt.lastError),
      httpStatus: attempt.httpStatus,
      responseBody: this.redactString(attempt.responseBody),
      payloadMetadata,
      createdAt: attempt.createdAt,
      updatedAt: attempt.updatedAt,
      deliveredAt: attempt.deliveredAt,
    };
  }

  async listDeliveryAttempts(
    publicKey: string,
    filters: {
      endpointId?: string;
      status?: string;
      eventType?: string;
      limit?: number;
      cursor?: string;
    } = {},
  ): Promise<{ data: WebhookDeliveryAttemptDto[]; next_cursor: string | null; has_more: boolean }> {
    return this.listWebhookDeliveryAttempts(publicKey, filters);
  }

  async getDeliveryAttempt(
    publicKey: string,
    endpointId: string,
    attemptId: string,
  ): Promise<WebhookDeliveryAttemptDetailDto | null> {
    return this.getWebhookDeliveryAttempt(publicKey, endpointId, attemptId);
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
   * Trigger immediate redelivery of a specific event via the replay service.
   */
  async redeliverEvent(
    publicKey: string,
    webhookId: string,
    eventId: string,
    eventType: string,
  ): Promise<WebhookRedeliverResponseDto> {
    return this.replayService.replayDelivery(
      publicKey,
      webhookId,
      eventId,
      eventType,
    );
  }

  async getDeliveryStatus(
    publicKey: string,
    eventId: string,
    eventType: string,
  ): Promise<WebhookDeliveryStatusDto> {
    return this.replayService.getDeliveryStatus(publicKey, eventId, eventType);
  }

  async getReplayHistory(
    webhookId: string,
    limit?: number,
  ): Promise<WebhookReplayLogDto[]> {
    return this.replayService.listReplayHistory(webhookId, limit);
  }

  private generateSecret(): string {
    const bytes = crypto.randomBytes(32);
    return `whsec_${bytes.toString("hex")}`;
  }

  private redactString(value?: string | null): string | undefined {
    if (!value) return undefined;
    const sanitized = value
      .replace(/(whsec_|sec_|sk_live_|sk_test_)[A-Za-z0-9_\-]+/g, "$1[REDACTED]")
      .replace(/(authorization|api[-_ ]?key|signature|secret|token)([\"'\s:=]+)([^,}\]\s\"']+)/gi, "$1$2[REDACTED]")
      .replace(/\bBearer\s+[A-Za-z0-9._-]+/gi, "Bearer [REDACTED]");
    return sanitized.length > 2000 ? `${sanitized.slice(0, 2000)}…` : sanitized;
  }

  private redactPayloadMetadata(payload: Record<string, unknown>): Record<string, unknown> {
    const redacted = Object.fromEntries(
      Object.entries(payload).map(([key, value]) => {
        const normalizedKey = key.toLowerCase();
        const isSensitive = /secret|token|authorization|signature|api[-_ ]?key|password|cookie/i.test(normalizedKey);
        if (isSensitive || typeof value === "string" && /(whsec_|sk_live_|sk_test_|Bearer\s+)/i.test(value)) {
          return [key, "[REDACTED]"];
        }
        if (typeof value === "string") {
          return [key, this.redactString(value) ?? "[REDACTED]"];
        }
        if (value && typeof value === "object") {
          return [key, this.redactPayloadMetadata(value as Record<string, unknown>)];
        }
        return [key, value];
      }),
    );

    return Object.fromEntries(
      Object.entries(redacted).filter(([, value]) => value !== undefined && value !== null),
    );
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
