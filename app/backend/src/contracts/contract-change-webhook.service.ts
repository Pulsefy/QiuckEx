import { Injectable, Logger } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';

interface AdminWebhookSubscription {
  id: string;
  webhookUrl: string;
  secret: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

@Injectable()
export class ContractChangeWebhookService {
  private readonly logger = new Logger(ContractChangeWebhookService.name);
  private readonly fallbackStore = new Map<string, AdminWebhookSubscription[]>();

  constructor(private readonly supabaseService: SupabaseService) {}

  async registerWebhook(
    webhookUrl: string,
    secret?: string,
  ): Promise<AdminWebhookSubscription> {
    const id = `cwh_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
    const now = new Date().toISOString();

    const subscription: AdminWebhookSubscription = {
      id,
      webhookUrl,
      secret: secret ?? this.generateSecret(),
      enabled: true,
      createdAt: now,
      updatedAt: now,
    };

    await this.persistSubscription(subscription);

    this.logger.log(`Registered contract change webhook: ${webhookUrl}`);
    return subscription;
  }

  async listWebhooks(): Promise<AdminWebhookSubscription[]> {
    try {
      const client = this.supabaseService.getClient();
      const { data, error } = await client
        .from('contract_change_webhooks')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;
      return (data ?? []).map((row) => this.mapRow(row));
    } catch (error) {
      this.logger.warn(
        `Falling back to in-memory webhook store: ${(error as Error).message}`,
      );
      return this.fallbackStore.get('contract-change-webhooks') ?? [];
    }
  }

  async deleteWebhook(id: string): Promise<boolean> {
    try {
      const client = this.supabaseService.getClient();
      const { error } = await client
        .from('contract_change_webhooks')
        .delete()
        .eq('id', id);

      if (error) throw error;
    } catch (error) {
      this.logger.warn(
        `Unable to delete webhook from store: ${(error as Error).message}`,
      );
    }

    const fallback = this.fallbackStore.get('contract-change-webhooks') ?? [];
    const exists = fallback.some((w) => w.id === id);
    this.fallbackStore.set(
      'contract-change-webhooks',
      fallback.filter((w) => w.id !== id),
    );
    return exists;
  }

  async getEnabledWebhooks(): Promise<AdminWebhookSubscription[]> {
    try {
      const client = this.supabaseService.getClient();
      const { data, error } = await client
        .from('contract_change_webhooks')
        .select('*')
        .eq('enabled', true);

      if (error) throw error;
      return (data ?? []).map((row) => this.mapRow(row));
    } catch (error) {
      this.logger.warn(
        `Unable to fetch enabled webhooks: ${(error as Error).message}`,
      );
      return (this.fallbackStore.get('contract-change-webhooks') ?? []).filter(
        (w) => w.enabled,
      );
    }
  }

  private async persistSubscription(
    subscription: AdminWebhookSubscription,
  ): Promise<void> {
    try {
      const client = this.supabaseService.getClient();
      const { error } = await client
        .from('contract_change_webhooks')
        .upsert(
          {
            id: subscription.id,
            webhook_url: subscription.webhookUrl,
            secret: subscription.secret,
            enabled: subscription.enabled,
            created_at: subscription.createdAt,
            updated_at: subscription.updatedAt,
          },
          { onConflict: 'id' },
        );

      if (error) throw error;
    } catch (error) {
      this.logger.warn(
        `Unable to persist webhook subscription: ${(error as Error).message}`,
      );
      const fallback = this.fallbackStore.get('contract-change-webhooks') ?? [];
      fallback.push(subscription);
      this.fallbackStore.set('contract-change-webhooks', fallback);
    }
  }

  private generateSecret(): string {
    return `cwhsec_${Math.random().toString(36).slice(2, 15)}`;
  }

  private mapRow(row: Record<string, unknown>): AdminWebhookSubscription {
    return {
      id: String(row.id),
      webhookUrl: String(row.webhook_url),
      secret: String(row.secret ?? ''),
      enabled: Boolean(row.enabled),
      createdAt: String(row.created_at),
      updatedAt: String(row.updated_at),
    };
  }
}
