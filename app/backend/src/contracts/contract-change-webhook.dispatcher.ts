import { Injectable, Logger } from '@nestjs/common';
import { createHmac } from 'crypto';

const WEBHOOK_DELIVERY_TIMEOUT_MS = 10_000;

export interface WebhookDispatchResult {
  webhookId: string;
  url: string;
  success: boolean;
  httpStatus?: number;
  error?: string;
}

@Injectable()
export class ContractChangeWebhookDispatcher {
  private readonly logger = new Logger(
    ContractChangeWebhookDispatcher.name,
  );

  async dispatch(
    webhooks: { id: string; webhookUrl: string; secret: string }[],
    payload: Record<string, unknown>,
  ): Promise<WebhookDispatchResult[]> {
    const results: WebhookDispatchResult[] = [];

    if (!webhooks.length) return results;

    const body = JSON.stringify({
      event: 'contract_registry.changed',
      occurredAt: new Date().toISOString(),
      payload,
    });

    await Promise.allSettled(
      webhooks.map(async (webhook) => {
        const controller = new AbortController();
        const timeout = setTimeout(
          () => controller.abort(),
          WEBHOOK_DELIVERY_TIMEOUT_MS,
        );

        try {
          const signature = createHmac('sha256', webhook.secret)
            .update(body)
            .digest('hex');

          const response = await fetch(webhook.webhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-QuickEx-Signature': signature,
              'X-QuickEx-Event': 'contract_registry.changed',
            },
            body,
            signal: controller.signal,
          });

          results.push({
            webhookId: webhook.id,
            url: webhook.webhookUrl,
            success: response.ok,
            httpStatus: response.status,
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Unknown error';
          results.push({
            webhookId: webhook.id,
            url: webhook.webhookUrl,
            success: false,
            error: controller.signal.aborted
              ? `Webhook delivery timed out after ${WEBHOOK_DELIVERY_TIMEOUT_MS}ms`
              : message,
          });
        } finally {
          clearTimeout(timeout);
        }
      }),
    );

    const failures = results.filter((r) => !r.success);
    if (failures.length > 0) {
      this.logger.warn(
        `Failed to deliver contract change webhook to ${failures.length}/${results.length} endpoints`,
      );
    }

    return results;
  }
}
