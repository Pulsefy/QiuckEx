import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import * as crypto from 'crypto';

import { ApiKeysService } from '../api-keys/api-keys.service';
import { ApiKeyCreated } from '../api-keys/api-keys.types';
import { WebhookService } from '../notifications/webhook.service';
import { AuditService } from '../audit/audit.service';

import {
  BulkRevokeDto,
  BulkRevokeResultDto,
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
    const webhook = await this.webhookService.getWebhook(webhookId);
    if (!webhook) throw new NotFoundException('Webhook not found');

    const sentAt = new Date().toISOString();
    const testEventId = `test_${crypto.randomUUID()}`;
    const payload = {
      eventType: 'payment.received',
      eventId: testEventId,
      recipientPublicKey: webhook.publicKey,
      payload: { test: true, source: 'developer_self_service_api' },
      timestamp: sentAt,
    };

    const bodyStr = JSON.stringify(payload);
    const ts = Date.now();
    const signature = this.signPayload(webhook.secret, bodyStr, ts);

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
          'X-QX-Signature': signature,
          'X-QX-Event': 'payment.received',
          'X-QX-Event-Id': testEventId,
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
      'webhook.test',
      webhookId,
      { target_url: webhook.webhookUrl, http_status: httpStatus, success, latency_ms: latencyMs },
    );

    return {
      success,
      webhook_id: webhookId,
      target_url: webhook.webhookUrl,
      http_status: httpStatus,
      response_body: responseBody,
      latency_ms: latencyMs,
      sent_at: sentAt,
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
}
