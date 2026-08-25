import { Injectable, Logger } from "@nestjs/common";
import * as crypto from "crypto";

import { NotificationPreferencesRepository } from "./notification-preferences.repository";
import { NotificationLogRepository } from "./notification-log.repository";
import { WebhookReplayService } from "./webhook-replay.service";
import type { NotificationPreference } from "./types/notification.types";
import {
  redactSensitiveText,
  redactPayloadMetadata,
} from "./utils/redaction.util";
import type {
  CreateWebhookDto,
  UpdateWebhookDto,
  WebhookResponseDto,
  WebhookDeliveryLogDto,
  WebhookStatsDto,
  WebhookDeliveryStatusDto,
  WebhookReplayLogDto,
  WebhookRedeliverResponseDto,
  WebhookHistoryQueryDto,
  WebhookDeliveryDetailDto,
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
    filters?: { status?: string; eventType?: string },
  ): Promise<{ data: WebhookDeliveryLogDto[]; next_cursor: string | null; has_more: boolean }> {
    const result = await this.logRepo.getWebhookDeliveryLogsPaginated(publicKey, limit, cursor, filters);
    const webhooks = await this.prefsRepo.getWebhooksByPublicKey(publicKey);
    const primaryWebhook = webhooks[0];

    return {
      data: result.data.map((log) => ({
        id: log.id,
        webhookId: primaryWebhook?.id,
        endpointUrl: primaryWebhook?.webhookUrl,
        eventType: log.eventType,
        eventId: log.eventId,
        status: log.status,
        attempts: log.attempts,
        lastError: log.lastError ? redactSensitiveText(log.lastError) : undefined,
        httpStatus: log.httpStatus,
        responseBody: log.responseBody ? redactSensitiveText(log.responseBody) : undefined,
        createdAt: log.createdAt,
        updatedAt: log.updatedAt,
        deliveredAt: log.deliveredAt,
        payloadMetadata: log.payloadMetadata ? redactPayloadMetadata(log.payloadMetadata) : undefined,
      })),
      next_cursor: result.next_cursor,
      has_more: result.has_more,
    };
  }

  /**
   * Query delivery history for a public key with filtering by endpoint, status, and eventType.
   */
  async getDeliveryHistory(
    publicKey: string,
    query: WebhookHistoryQueryDto,
  ): Promise<{ data: WebhookDeliveryLogDto[]; next_cursor: string | null; has_more: boolean }> {
    let targetPublicKey = publicKey;
    let endpointWebhook: NotificationPreference | null = null;

    if (query.endpoint) {
      const webhook = await this.prefsRepo.getWebhookById(query.endpoint);
      if (!webhook || webhook.publicKey !== publicKey) {
        // Cross-tenant or non-existent endpoint access attempt
        return { data: [], next_cursor: null, has_more: false };
      }
      endpointWebhook = webhook;
    }

    const result = await this.getDeliveryLogs(targetPublicKey, query.limit, query.cursor, {
      status: query.status,
      eventType: query.eventType,
    });

    if (endpointWebhook) {
      return {
        ...result,
        data: result.data.map((log) => ({
          ...log,
          webhookId: endpointWebhook!.id,
          endpointUrl: endpointWebhook!.webhookUrl,
        })),
      };
    }

    return result;
  }

  /**
   * Get single delivery attempt detail by log ID for a public key with access control.
   */
  async getDeliveryDetail(
    publicKey: string,
    logId: string,
  ): Promise<WebhookDeliveryDetailDto | null> {
    const log = await this.logRepo.getWebhookDeliveryLogById(publicKey, logId);
    if (!log) return null;

    const webhooks = await this.prefsRepo.getWebhooksByPublicKey(publicKey);
    const primaryWebhook = webhooks[0];

    const attempts = Math.max(log.attempts, 1);
    const attemptHistory = Array.from({ length: attempts }, (_, index) => {
      const attemptNumber = index + 1;
      const isLast = attemptNumber === attempts;
      const rawError = isLast ? log.lastError : undefined;
      return {
        attemptNumber,
        status: isLast ? log.status : "retried",
        httpStatus: isLast ? log.httpStatus : undefined,
        error: rawError ? redactSensitiveText(rawError) : undefined,
        timestamp: isLast ? (log.deliveredAt ?? log.updatedAt) : log.createdAt,
      };
    });

    const redactedLastError = log.lastError ? redactSensitiveText(log.lastError) : undefined;
    const redactedResponseBody = log.responseBody ? redactSensitiveText(log.responseBody) : undefined;

    return {
      id: log.id,
      webhookId: primaryWebhook?.id,
      endpointUrl: primaryWebhook?.webhookUrl,
      eventType: log.eventType,
      eventId: log.eventId,
      status: log.status,
      attempts: log.attempts,
      maxAttempts: 3,
      lastError: redactedLastError,
      dlqReason: log.status === "dlq" ? (redactedLastError ?? "Exhausted retries") : undefined,
      httpStatus: log.httpStatus,
      responseBody: redactedResponseBody,
      createdAt: log.createdAt,
      updatedAt: log.updatedAt,
      deliveredAt: log.deliveredAt,
      payloadMetadata: log.payloadMetadata ? redactPayloadMetadata(log.payloadMetadata) : undefined,
      attemptHistory,
    };
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
