import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import * as crypto from 'crypto';

import { ApiKeysService } from '../api-keys/api-keys.service';
import { ApiKeyCreated } from '../api-keys/api-keys.types';
import { WebhookService } from '../notifications/webhook.service';
import { AuditService } from '../audit/audit.service';

import {
  BulkRevokeDto,
  BulkRevokeResultDto,
  WebhookSampleEventDto,
  WebhookSampleEventType,
  WebhookTestResultDto,
  IntegrationHealthDto,
  PingResponseDto,
} from './dto/developer.dto';

const VERSION = '0.1.0';
const TEST_WEBHOOK_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BODY_LENGTH = 2048;

@Injectable()
export class DeveloperService {
  private readonly logger = new Logger(DeveloperService.name);

  constructor(
    private readonly apiKeysService: ApiKeysService,
    private readonly webhookService: WebhookService,
    private readonly auditService: AuditService,
  ) {}

  ping(): PingResponseDto {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      version: VERSION,
    };
  }

  async testWebhook(webhookId: string): Promise<WebhookTestResultDto> {
    return this.sendSampleWebhookEvent(webhookId, {
      event_type: 'payment.received',
      include_signature: true,
    }, 'webhook.test');
  }

  async sendSampleWebhookEvent(
    webhookId: string,
    dto: WebhookSampleEventDto = {},
    auditAction = 'webhook.sample',
  ): Promise<WebhookTestResultDto> {
    const webhook = await this.webhookService.getWebhook(webhookId);
    if (!webhook) throw new NotFoundException('Webhook not found');

    const eventType = dto.event_type ?? 'payment.received';
    const sentAt = dto.timestamp ?? new Date().toISOString();
    const eventId = `sample_${eventType.replace('.', '_')}_${crypto.randomUUID()}`;
    const payload = {
      eventType,
      eventId,
      recipientPublicKey: webhook.publicKey,
      payload: this.buildSamplePayload(eventType, webhook.publicKey, sentAt),
      timestamp: sentAt,
    };

    const bodyStr = JSON.stringify(payload);
    const includeSignature = dto.include_signature ?? true;
    const ts = new Date(sentAt).getTime();
    const signature = includeSignature
      ? this.signPayload(webhook.secret, bodyStr, ts)
      : undefined;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TEST_WEBHOOK_TIMEOUT_MS);

    const start = Date.now();
    let httpStatus: number | null = null;
    let responseBody: string | null = null;
    let success = false;

    try {
      const res = await fetch(webhook.webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(signature ? { 'X-QX-Signature': signature } : {}),
          ...(includeSignature ? { 'X-QX-Timestamp': String(ts) } : {}),
          'X-QX-Event': eventType,
          'X-QX-Event-Id': eventId,
          'X-QX-Test': 'true',
          'User-Agent': 'QuickEx-Webhook/1.0',
        },
        body: bodyStr,
        signal: controller.signal,
      });

      httpStatus = res.status;
      success = res.ok;

      try {
        const text = await res.text();
        responseBody = text.length > MAX_RESPONSE_BODY_LENGTH
          ? text.slice(0, MAX_RESPONSE_BODY_LENGTH) + '...'
          : text;
      } catch {
        // ignore body read errors
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`Test webhook delivery failed for ${webhookId}: ${msg}`);
      responseBody = msg;
    } finally {
      clearTimeout(timer);
    }

    const latencyMs = Date.now() - start;

    await this.auditService.log(
      'developer_api',
      auditAction,
      webhookId,
      {
        target_url: webhook.webhookUrl,
        http_status: httpStatus,
        success,
        latency_ms: latencyMs,
        event_type: eventType,
        signature_included: includeSignature,
      },
    );

    return {
      success,
      webhook_id: webhookId,
      target_url: webhook.webhookUrl,
      http_status: httpStatus,
      response_body: responseBody,
      latency_ms: latencyMs,
      sent_at: sentAt,
      event_type: eventType,
      event_id: eventId,
      signature_included: includeSignature,
    };
  }

  async bulkRevoke(dto: BulkRevokeDto): Promise<BulkRevokeResultDto> {
    const results = await Promise.allSettled(
      dto.ids.map((id) => this.apiKeysService.revoke(id).then(() => id)),
    );

    const revoked: string[] = [];
    const failed: { id: string; reason: string }[] = [];

    results.forEach((result, idx) => {
      if (result.status === 'fulfilled') {
        revoked.push(result.value);
      } else {
        failed.push({
          id: dto.ids[idx],
          reason: result.reason instanceof Error ? result.reason.message : String(result.reason),
        });
      }
    });

    await this.auditService.log(
      'developer_api',
      'keys.bulk_revoke',
      undefined,
      { requested: dto.ids, revoked, failed: failed.map((f) => f.id) },
    );

    return {
      revoked,
      failed,
      total: dto.ids.length,
      success_count: revoked.length,
      failure_count: failed.length,
    };
  }

  async emergencyRotate(id: string): Promise<ApiKeyCreated> {
    const result = await this.apiKeysService.emergencyRotate(id);

    await this.auditService.log(
      'developer_api',
      'keys.emergency_rotate',
      id,
      { new_prefix: result.key_prefix },
    );

    return result;
  }

  async getIntegrationHealth(ownerId: string): Promise<IntegrationHealthDto> {
    const [usage, webhookStats] = await Promise.all([
      this.apiKeysService.getUsage(ownerId),
      this.webhookService.getStats(ownerId),
    ]);

    const totalDeliveries = webhookStats.totalSent + webhookStats.totalFailed;
    const webhookFailureRate = totalDeliveries > 0
      ? webhookStats.totalFailed / totalDeliveries
      : 0;
    const webhookScore = Math.round(60 * (1 - webhookFailureRate));

    const quotaUtilization = usage.quota > 0
      ? usage.total_requests / usage.quota
      : 0;
    const quotaScore = quotaUtilization <= 0.9
      ? Math.round(40 * (1 - Math.max(0, quotaUtilization - 0.7) / 0.3))
      : 0;

    const score = Math.min(100, Math.max(0, webhookScore + quotaScore));
    const grade = this.toGrade(score);

    await this.auditService.log(
      'developer_api',
      'health.score',
      ownerId,
      { score, grade, webhook_failure_rate: webhookFailureRate, quota_utilization: quotaUtilization },
    );

    return {
      score,
      grade,
      components: {
        webhook_failure_rate: webhookFailureRate,
        quota_utilization: quotaUtilization,
        webhook_score: webhookScore,
        quota_score: quotaScore,
      },
      computed_at: new Date().toISOString(),
    };
  }

  private toGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 90) return 'A';
    if (score >= 75) return 'B';
    if (score >= 60) return 'C';
    if (score >= 45) return 'D';
    return 'F';
  }

  private signPayload(secret: string, body: string, timestamp: number): string {
    const signed = `${timestamp}.${body}`;
    const hmac = crypto.createHmac('sha256', secret).update(signed).digest('hex');
    return `t=${timestamp},v1=${hmac}`;
  }

  private buildSamplePayload(
    eventType: WebhookSampleEventType,
    recipientPublicKey: string,
    timestamp: string,
  ): Record<string, unknown> {
    const base = {
      test: true,
      source: 'developer_self_service_api',
      schema_version: '2026-04-29',
    };

    switch (eventType) {
      case 'link.created':
        return {
          ...base,
          link_id: 'plink_sample_01',
          creator_public_key: recipientPublicKey,
          asset: 'XLM',
          amount: '25.0000000',
          memo: 'QuickEx sample payment link',
          expires_at: new Date(new Date(timestamp).getTime() + 86_400_000).toISOString(),
        };
      case 'payment.received':
        return {
          ...base,
          payment_id: 'pay_sample_received_01',
          link_id: 'plink_sample_01',
          from_public_key: 'GBZXN7PIRZGNMHGA6U2QBG7A5XBQ2YH6R3MGNJ2T63PXWKBUI5V3R2ZU',
          to_public_key: recipientPublicKey,
          asset: 'XLM',
          amount: '25.0000000',
          tx_hash: 'sample_received_tx_hash',
        };
      case 'payment.settled':
        return {
          ...base,
          payment_id: 'pay_sample_settled_01',
          settlement_id: 'set_sample_01',
          recipient_public_key: recipientPublicKey,
          asset: 'XLM',
          amount: '25.0000000',
          fee_amount: '0.1000000',
          settled_at: timestamp,
          tx_hash: 'sample_settlement_tx_hash',
        };
      case 'payment.failed':
        return {
          ...base,
          payment_id: 'pay_sample_failed_01',
          link_id: 'plink_sample_01',
          recipient_public_key: recipientPublicKey,
          asset: 'XLM',
          amount: '25.0000000',
          failure_code: 'INSUFFICIENT_BALANCE',
          failure_message: 'Sample failure: sender balance was too low.',
        };
    }
  }
}
