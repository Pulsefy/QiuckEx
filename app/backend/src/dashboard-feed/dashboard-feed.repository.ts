import { Injectable, Logger } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import type {
  FeedItem,
  PaymentFeedDetail,
  RefundFeedDetail,
  WebhookFeedDetail,
  NotificationFeedDetail,
  ContractFeedDetail,
  UsernameFeedDetail,
} from './dashboard-feed.types';

/** Row shapes returned from Supabase queries. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Row = Record<string, any>;

@Injectable()
export class DashboardFeedRepository {
  private readonly logger = new Logger(DashboardFeedRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  /**
   * Fetch payment feed items for the given address.
   * Ordered by created_at DESC, id DESC for deterministic pagination.
   */
  async getPayments(
    address: string,
    after?: string,
    before?: string,
    limit: number = 50,
  ): Promise<FeedItem[]> {
    const client = this.supabase.getClient();
    let query = client
      .from('payment_records')
      .select('id, status, created_at, amount, asset_code, sender_address, receiver_address, tx_hash')
      .or(`sender_address.eq.${address},receiver_address.eq.${address}`)
      .order('created_at', { ascending: false })
      .order('id', { ascending: false });

    if (after) query = query.gt('created_at', after);
    if (before) query = query.lt('created_at', before);

    const { data, error } = await query.limit(limit + 1);
    if (error) throw error;
    if (!data || data.length === 0) return [];

    return (data as Row[]).slice(0, limit).map((row) => this.mapPayment(row));
  }

  /**
   * Fetch refund feed items for the given address (via actor_id).
   */
  async getRefunds(
    address: string,
    after?: string,
    before?: string,
    limit: number = 50,
  ): Promise<FeedItem[]> {
    const client = this.supabase.getClient();
    let query = client
      .from('refund_attempts')
      .select('id, entity_type, entity_id, reason_code, status, actor_id, created_at')
      .eq('actor_id', address)
      .order('created_at', { ascending: false })
      .order('id', { ascending: false });

    if (after) query = query.gt('created_at', after);
    if (before) query = query.lt('created_at', before);

    const { data, error } = await query.limit(limit + 1);
    if (error) throw error;
    if (!data || data.length === 0) return [];

    return (data as Row[]).slice(0, limit).map((row) => this.mapRefund(row));
  }

  /**
   * Fetch webhook delivery feed items for the given address.
   */
  async getWebhookDeliveries(
    address: string,
    after?: string,
    before?: string,
    limit: number = 50,
  ): Promise<FeedItem[]> {
    const client = this.supabase.getClient();
    let query = client
      .from('notification_log')
      .select(
        'id, event_type, event_id, status, attempts, last_error, webhook_response_status, webhook_delivered_at, created_at',
      )
      .eq('public_key', address)
      .eq('channel', 'webhook')
      .order('created_at', { ascending: false })
      .order('id', { ascending: false });

    if (after) query = query.gt('created_at', after);
    if (before) query = query.lt('created_at', before);

    const { data, error } = await query.limit(limit + 1);
    if (error) throw error;
    if (!data || data.length === 0) return [];

    return (data as Row[]).slice(0, limit).map((row) => this.mapWebhook(row));
  }

  /**
   * Fetch in-app notification feed items for the given address.
   */
  async getNotifications(
    address: string,
    after?: string,
    before?: string,
    limit: number = 50,
  ): Promise<FeedItem[]> {
    const client = this.supabase.getClient();
    let query = client
      .from('in_app_notifications')
      .select('id, "publicKey", "eventType", "eventId", title, body, read, "createdAt"')
      .eq('publicKey', address)
      .order('createdAt', { ascending: false })
      .order('id', { ascending: false });

    if (after) query = query.gt('createdAt', after);
    if (before) query = query.lt('createdAt', before);

    const { data, error } = await query.limit(limit + 1);
    if (error) throw error;
    if (!data || data.length === 0) return [];

    return (data as Row[]).slice(0, limit).map((row) => this.mapNotification(row));
  }

  /**
   * Fetch contract event feed items.
   * Contract events are not per-address; we return recent enabled webhooks.
   */
  async getContractEvents(
    after?: string,
    before?: string,
    limit: number = 50,
  ): Promise<FeedItem[]> {
    const client = this.supabase.getClient();
    let query = client
      .from('contract_change_webhooks')
      .select('id, webhook_url, enabled, created_at, updated_at')
      .eq('enabled', true)
      .order('updated_at', { ascending: false })
      .order('id', { ascending: false });

    if (after) query = query.gt('updated_at', after);
    if (before) query = query.lt('updated_at', before);

    const { data, error } = await query.limit(limit + 1);
    if (error) throw error;
    if (!data || data.length === 0) return [];

    return (data as Row[]).slice(0, limit).map((row) => this.mapContract(row));
  }

  /**
   * Fetch username-related activity (recent registrations).
   */
  async getUsernameActions(
    address: string,
    after?: string,
    before?: string,
    limit: number = 50,
  ): Promise<FeedItem[]> {
    const client = this.supabase.getClient();
    let query = client
      .from('usernames')
      .select('id, username, public_key, created_at')
      .eq('public_key', address)
      .order('created_at', { ascending: false })
      .order('id', { ascending: false });

    if (after) query = query.gt('created_at', after);
    if (before) query = query.lt('created_at', before);

    const { data, error } = await query.limit(limit + 1);
    if (error) throw error;
    if (!data || data.length === 0) return [];

    return (data as Row[]).slice(0, limit).map((row) => this.mapUsername(row));
  }

  // ── Mappers ──────────────────────────────────────────────────────────────

  private mapPayment(row: Row): FeedItem {
    const detail: PaymentFeedDetail = {
      txHash: String(row.tx_hash ?? ''),
      amount: String(row.amount ?? '0'),
      asset: String(row.asset_code ?? 'XLM'),
      sender: String(row.sender_address ?? ''),
      receiver: String(row.receiver_address ?? ''),
      status: String(row.status ?? 'unknown'),
    };

    return {
      id: `pay_${row.id}`,
      kind: 'payment',
      timestamp: String(row.created_at),
      title: `Payment ${detail.status}`,
      description: `${detail.amount} ${detail.asset} from ${this.shortKey(detail.sender)} to ${this.shortKey(detail.receiver)}`,
      status: row.status === 'completed' ? 'success' : 'pending',
      correlationId: detail.txHash || null,
      paymentDetail: detail,
      refundDetail: null,
      webhookDetail: null,
      notificationDetail: null,
      contractDetail: null,
      usernameDetail: null,
    };
  }

  private mapRefund(row: Row): FeedItem {
    const detail: RefundFeedDetail = {
      refundId: String(row.id),
      entityType: String(row.entity_type),
      entityId: String(row.entity_id),
      reasonCode: String(row.reason_code ?? ''),
      refundStatus: String(row.status),
    };

    const statusMap: Record<string, FeedItem['status']> = {
      approved: 'success',
      pending: 'pending',
      rejected: 'cancelled',
      failed: 'failed',
    };

    return {
      id: `ref_${row.id}`,
      kind: 'refund',
      timestamp: String(row.created_at),
      title: `Refund ${detail.refundStatus}`,
      description: `${detail.reasonCode} — entity ${detail.entityType}:${detail.entityId}`,
      status: statusMap[detail.refundStatus] ?? 'pending',
      correlationId: null,
      paymentDetail: null,
      refundDetail: detail,
      webhookDetail: null,
      notificationDetail: null,
      contractDetail: null,
      usernameDetail: null,
    };
  }

  private mapWebhook(row: Row): FeedItem {
    const detail: WebhookFeedDetail = {
      webhookLogId: String(row.id),
      eventType: String(row.event_type),
      eventId: String(row.event_id),
      deliveryStatus: String(row.status),
      attempts: Number(row.attempts ?? 0),
      httpStatus: row.webhook_response_status != null ? Number(row.webhook_response_status) : null,
      lastError: row.last_error != null ? String(row.last_error) : null,
      deliveredAt: row.webhook_delivered_at != null ? String(row.webhook_delivered_at) : null,
    };

    const statusMap: Record<string, FeedItem['status']> = {
      sent: 'success',
      pending: 'pending',
      failed: 'failed',
      dlq: 'dlq',
    };

    return {
      id: `whk_${row.id}`,
      kind: 'webhook_delivery',
      timestamp: String(row.created_at),
      title: `Webhook ${detail.eventType} — ${detail.deliveryStatus}`,
      description: detail.lastError
        ? `Delivery failed: ${detail.lastError}`
        : `Delivered after ${detail.attempts} attempt(s)`,
      status: statusMap[detail.deliveryStatus] ?? 'pending',
      correlationId: detail.eventId || null,
      paymentDetail: null,
      refundDetail: null,
      webhookDetail: detail,
      notificationDetail: null,
      contractDetail: null,
      usernameDetail: null,
    };
  }

  private mapNotification(row: Row): FeedItem {
    const detail: NotificationFeedDetail = {
      notificationId: String(row.id),
      eventType: String(row.eventType),
      eventId: String(row.eventId),
      title: String(row.title),
      body: String(row.body),
      read: Boolean(row.read),
    };

    return {
      id: `notif_${row.id}`,
      kind: 'notification',
      timestamp: String(row.createdAt),
      title: detail.title,
      description: detail.body,
      status: detail.read ? 'read' : 'unread',
      correlationId: detail.eventId || null,
      paymentDetail: null,
      refundDetail: null,
      webhookDetail: null,
      notificationDetail: detail,
      contractDetail: null,
      usernameDetail: null,
    };
  }

  private mapContract(row: Row): FeedItem {
    const detail: ContractFeedDetail = {
      contractWebhookId: String(row.id),
      webhookUrl: String(row.webhook_url),
      enabled: Boolean(row.enabled),
    };

    return {
      id: `ctr_${row.id}`,
      kind: 'contract_event',
      timestamp: String(row.updated_at ?? row.created_at),
      title: 'Contract webhook triggered',
      description: `Webhook endpoint: ${detail.webhookUrl}`,
      status: 'success',
      correlationId: null,
      paymentDetail: null,
      refundDetail: null,
      webhookDetail: null,
      notificationDetail: null,
      contractDetail: detail,
      usernameDetail: null,
    };
  }

  private mapUsername(row: Row): FeedItem {
    const detail: UsernameFeedDetail = {
      username: String(row.username),
      publicKey: String(row.public_key),
    };

    return {
      id: `uname_${row.id}`,
      kind: 'username_action',
      timestamp: String(row.created_at),
      title: `Username claimed: ${detail.username}`,
      description: `Username ${detail.username} registered for ${this.shortKey(detail.publicKey)}`,
      status: 'success',
      correlationId: null,
      paymentDetail: null,
      refundDetail: null,
      webhookDetail: null,
      notificationDetail: null,
      contractDetail: null,
      usernameDetail: detail,
    };
  }

  private shortKey(key: string): string {
    if (key.length <= 12) return key;
    return `${key.slice(0, 6)}…${key.slice(-4)}`;
  }
}
