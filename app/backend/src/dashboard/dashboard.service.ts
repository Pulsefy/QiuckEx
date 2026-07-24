import {
  Injectable,
  Logger,
} from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import { PAGINATION_DEFAULTS, encodeCursor, decodeCursor } from '../common/pagination/cursor.util';
import { FeedItemType } from './dto/feed-query.dto';
import {
  FeedItemDto,
  PaymentFeedData,
  RefundFeedData,
  NotificationFeedData,
  ContractActionFeedData,
  UsernameClaimFeedData,
  WebhookDeliveryFeedData,
} from './dto/feed-response.dto';

// ── Types for raw DB rows ────────────────────────────────────────────────────

interface PaymentRecordRow {
  id: string;
  sender_public_key?: string;
  receiver_public_key?: string;
  amount_usd?: number;
  asset_code?: string;
  asset_issuer?: string;
  status?: string;
  tx_hash?: string;
  memo?: string;
  created_at: string;
}

interface RefundAttemptRow {
  id: string;
  entity_type: string;
  entity_id: string;
  reason_code: string | null;
  status: string;
  actor_id: string;
  created_at: string;
}

interface InAppNotificationRow {
  id: string;
  publicKey: string;
  eventType: string;
  eventId: string;
  title: string;
  body: string;
  read: boolean;
  metadata: Record<string, unknown> | null;
  createdAt: string;
}

interface EscrowRecordRow {
  id: string;
  owner: string;
  amount: string;
  token: string;
  commitment: string;
  status: string;
  tx_hash?: string;
  contract_id?: string;
  created_at: string;
}

interface UsernameRow {
  id: string;
  username: string;
  public_key: string;
  created_at: string;
}

interface WebhookLogRow {
  id: string;
  publicKey: string;
  channel: string;
  eventType: string;
  eventId: string;
  status: string;
  providerMessageId?: string;
  httpStatus?: number;
  lastError?: string;
  createdAt: string;
}

// ── Service ──────────────────────────────────────────────────────────────────

@Injectable()
export class DashboardService {
  private readonly logger = new Logger(DashboardService.name);

  constructor(private readonly supabase: SupabaseService) {}

  /**
   * Build the unified activity feed for a user.
   *
   * Strategy for correct cursor-based pagination across merged sources:
   * 1. Fetch `limit + 1` most-recent items from EACH enabled source without
   *    any cursor filter.
   * 2. Merge all results and sort deterministically (timestamp DESC, id DESC).
   * 3. If a cursor is present, find its position in the merged list and take
   *    the next `limit` items after it.
   * 4. If no cursor, take the first `limit` items.
   *
   * This avoids the incorrect behavior of passing a cursor from one source
   * type into a different source's DB query.
   */
  async getFeed(params: {
    publicKey?: string;
    types?: string;
    cursor?: string;
    limit?: number;
  }): Promise<{
    items: FeedItemDto[];
    pagination: { next_cursor: string | null; has_more: boolean; limit: number };
  }> {
    const limit = params.limit ?? PAGINATION_DEFAULTS.LIMIT_DEFAULT;
    const publicKey = params.publicKey;

    // Parse the requested types
    const typeFilter = params.types
      ? params.types.split(',').map((t) => t.trim().toLowerCase())
      : null;

    // Decode cursor for merged-list cutoff
    const cursorPayload = params.cursor
      ? decodeCursor(params.cursor)
      : null;

    // Fetch `limit + 1` from each source to have enough items for one page
    // even after cursor cutoff at the merged level.
    const fetchLimit = limit + 1;

    // Gather all feed items concurrently
    const feedPromises: Promise<FeedItemDto[]>[] = [];

    if (!typeFilter || typeFilter.includes(FeedItemType.PAYMENT)) {
      feedPromises.push(this.fetchPayments(publicKey, fetchLimit));
    }
    if (!typeFilter || typeFilter.includes(FeedItemType.REFUND)) {
      feedPromises.push(this.fetchRefunds(publicKey, fetchLimit));
    }
    if (!typeFilter || typeFilter.includes(FeedItemType.NOTIFICATION)) {
      feedPromises.push(this.fetchNotifications(publicKey, fetchLimit));
    }
    if (!typeFilter || typeFilter.includes(FeedItemType.CONTRACT_ACTION)) {
      feedPromises.push(this.fetchContractActions(publicKey, fetchLimit));
    }
    if (!typeFilter || typeFilter.includes(FeedItemType.USERNAME_CLAIM)) {
      feedPromises.push(this.fetchUsernameClaims(publicKey, fetchLimit));
    }
    if (!typeFilter || typeFilter.includes(FeedItemType.WEBHOOK_DELIVERY)) {
      feedPromises.push(this.fetchWebhookDeliveries(publicKey, fetchLimit));
    }

    const allResults = await Promise.allSettled(feedPromises);

    // Flatten and log rejected promises
    let items: FeedItemDto[] = [];
    for (const result of allResults) {
      if (result.status === 'fulfilled') {
        items.push(...result.value);
      } else {
        this.logger.warn(
          `Feed data source fetch failed: ${String(result.reason)}`,
        );
      }
    }

    // Deterministic sort: timestamp DESC, id DESC (tiebreaker)
    items.sort((a, b) => {
      const tsDiff =
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      if (tsDiff !== 0) return tsDiff;
      return b.id.localeCompare(a.id);
    });

    // Apply cursor cutoff at the merged level if a cursor was provided.
    // The cursor represents the last item the client has already seen.
    // We find the first item that should appear on the next page (i.e.,
    // the first item strictly before the cursor) and slice from there.
    // If the cursor item is no longer in the fetched window (stale cursor),
    // we return an empty page so the client doesn't re-see old items.
    if (cursorPayload) {
      const cursorIdx = items.findIndex(
        (i) =>
          i.timestamp < cursorPayload.pk ||
          (i.timestamp === cursorPayload.pk && i.id < cursorPayload.id),
      );
      items = cursorIdx >= 0 ? items.slice(cursorIdx) : [];
    }

    // Paginate: take up to `limit` items, detect if there are more
    const hasMore = items.length > limit;
    const page = hasMore ? items.slice(0, limit) : items;

    let nextCursor: string | null = null;
    if (hasMore && page.length > 0) {
      const last = page[page.length - 1];
      nextCursor = encodeCursor({
        pk: last.timestamp,
        id: last.id,
      });
    }

    return {
      items: page,
      pagination: {
        next_cursor: nextCursor,
        has_more: hasMore,
        limit,
      },
    };
  }

  // ── Individual fetchers (each returns FeedItemDto[]) ────────────────────────
  // Each fetcher returns the `limit` most-recent items from its source.
  // No cursor filtering — cursor pagination is handled at the merged level.

  private async fetchPayments(
    publicKey: string | undefined,
    limit: number,
  ): Promise<FeedItemDto[]> {
    try {
      const client = this.supabase.getClient();

      let query = client
        .from('payment_records')
        .select(
          'id, sender_public_key, receiver_public_key, amount_usd, asset_code, asset_issuer, status, tx_hash, memo, created_at',
        )
        .order('created_at', { ascending: false })
        .order('id', { ascending: false });

      if (publicKey) {
        query = query.or(
          `sender_public_key.eq.${publicKey},receiver_public_key.eq.${publicKey}`,
        );
      }

      query = query.limit(limit);

      const { data, error } = await query;
      if (error) {
        this.logger.warn(`Failed to fetch payments: ${error.message}`);
        return [];
      }

      return ((data ?? []) as PaymentRecordRow[]).map((row) => ({
        id: `pay_${row.id}`,
        type: FeedItemType.PAYMENT,
        timestamp: row.created_at,
        title: `Payment: ${row.amount_usd ?? '0'} ${row.asset_code ?? 'XLM'}`,
        description: row.tx_hash
          ? `Tx: ${row.tx_hash.slice(0, 12)}...`
          : undefined,
        data: {
          amount: String(row.amount_usd ?? '0'),
          asset: row.asset_code ?? 'XLM',
          status: (row.status as PaymentFeedData['status']) ?? 'Pending',
          sender: row.sender_public_key ?? '',
          receiver: row.receiver_public_key ?? null,
          txHash: row.tx_hash ?? '',
          memo: row.memo ?? null,
        } satisfies PaymentFeedData,
      }));
    } catch (err) {
      this.logger.warn(`Payment fetch error: ${String(err)}`);
      return [];
    }
  }

  private async fetchRefunds(
    publicKey: string | undefined,
    limit: number,
  ): Promise<FeedItemDto[]> {
    try {
      const client = this.supabase.getClient();

      let query = client
        .from('refund_attempts')
        .select(
          'id, entity_type, entity_id, reason_code, status, actor_id, created_at',
        )
        .order('created_at', { ascending: false })
        .order('id', { ascending: false });

      if (publicKey) {
        query = query.eq('actor_id', publicKey);
      }

      query = query.limit(limit);

      const { data, error } = await query;
      if (error) {
        this.logger.warn(`Failed to fetch refunds: ${error.message}`);
        return [];
      }

      return ((data ?? []) as RefundAttemptRow[]).map((row) => ({
        id: `ref_${row.id}`,
        type: FeedItemType.REFUND,
        timestamp: row.created_at,
        title: `Refund: ${row.entity_type} (${row.status})`,
        description: `Reason: ${row.reason_code ?? 'N/A'}`,
        data: {
          refundId: row.id,
          entityType: row.entity_type,
          entityId: row.entity_id,
          status: row.status,
          reasonCode: row.reason_code,
          actorId: row.actor_id,
        } satisfies RefundFeedData,
      }));
    } catch (err) {
      this.logger.warn(`Refund fetch error: ${String(err)}`);
      return [];
    }
  }

  private async fetchNotifications(
    publicKey: string | undefined,
    limit: number,
  ): Promise<FeedItemDto[]> {
    try {
      const client = this.supabase.getClient();

      let query = client
        .from('in_app_notifications')
        .select(
          'id, publicKey, eventType, eventId, title, body, read, metadata, createdAt',
        )
        .order('createdAt', { ascending: false })
        .order('id', { ascending: false });

      if (publicKey) {
        query = query.eq('publicKey', publicKey);
      }

      query = query.limit(limit);

      const { data, error } = await query;
      if (error) {
        this.logger.warn(`Failed to fetch notifications: ${error.message}`);
        return [];
      }

      return ((data ?? []) as InAppNotificationRow[]).map((row) => ({
        id: `noti_${row.id}`,
        type: FeedItemType.NOTIFICATION,
        timestamp: row.createdAt,
        title: row.title,
        description: row.body,
        data: {
          eventType: row.eventType,
          eventId: row.eventId,
          title: row.title,
          body: row.body,
          read: row.read,
          metadata: row.metadata,
        } satisfies NotificationFeedData,
      }));
    } catch (err) {
      this.logger.warn(`Notification fetch error: ${String(err)}`);
      return [];
    }
  }

  private async fetchContractActions(
    publicKey: string | undefined,
    limit: number,
  ): Promise<FeedItemDto[]> {
    try {
      const client = this.supabase.getClient();

      let query = client
        .from('escrow_records')
        .select(
          'id, owner, amount, token, commitment, status, tx_hash, contract_id, created_at',
        )
        .order('created_at', { ascending: false })
        .order('id', { ascending: false });

      if (publicKey) {
        query = query.eq('owner', publicKey);
      }

      query = query.limit(limit);

      const { data, error } = await query;
      if (error) {
        this.logger.warn(
          `Failed to fetch contract actions: ${error.message}`,
        );
        return [];
      }

      return ((data ?? []) as EscrowRecordRow[]).map((row) => ({
        id: `cont_${row.id}`,
        type: FeedItemType.CONTRACT_ACTION,
        timestamp: row.created_at,
        title: `Contract: ${row.status}`,
        description: `Escrow ${row.amount} ${row.token ?? 'XLM'}`,
        data: {
          contractId: row.contract_id ?? row.id,
          functionName: 'escrow',
          txHash: row.tx_hash ?? '',
          status: mapEscrowStatus(row.status),
          resourceFee: null,
        } satisfies ContractActionFeedData,
      }));
    } catch (err) {
      this.logger.warn(`Contract action fetch error: ${String(err)}`);
      return [];
    }
  }

  private async fetchUsernameClaims(
    publicKey: string | undefined,
    limit: number,
  ): Promise<FeedItemDto[]> {
    try {
      const client = this.supabase.getClient();

      let query = client
        .from('usernames')
        .select('id, username, public_key, created_at')
        .order('created_at', { ascending: false })
        .order('id', { ascending: false });

      if (publicKey) {
        query = query.eq('public_key', publicKey);
      }

      query = query.limit(limit);

      const { data, error } = await query;
      if (error) {
        this.logger.warn(
          `Failed to fetch username claims: ${error.message}`,
        );
        return [];
      }

      return ((data ?? []) as UsernameRow[]).map((row) => ({
        id: `user_${row.id}`,
        type: FeedItemType.USERNAME_CLAIM,
        timestamp: row.created_at,
        title: `Username claimed: @${row.username}`,
        description: `Registered by ${row.public_key.slice(0, 8)}...`,
        data: {
          username: row.username,
          publicKey: row.public_key,
        } satisfies UsernameClaimFeedData,
      }));
    } catch (err) {
      this.logger.warn(`Username claim fetch error: ${String(err)}`);
      return [];
    }
  }

  private async fetchWebhookDeliveries(
    publicKey: string | undefined,
    limit: number,
  ): Promise<FeedItemDto[]> {
    try {
      const client = this.supabase.getClient();

      let query = client
        .from('notification_log')
        .select(
          'id, publicKey, channel, eventType, eventId, status, httpStatus, lastError, createdAt',
        )
        .eq('channel', 'webhook')
        .order('createdAt', { ascending: false })
        .order('id', { ascending: false });

      if (publicKey) {
        query = query.eq('publicKey', publicKey);
      }

      query = query.limit(limit);

      const { data, error } = await query;
      if (error) {
        this.logger.warn(
          `Failed to fetch webhook deliveries: ${error.message}`,
        );
        return [];
      }

      return ((data ?? []) as WebhookLogRow[]).map((row) => ({
        id: `web_${row.id}`,
        type: FeedItemType.WEBHOOK_DELIVERY,
        timestamp: row.createdAt,
        title: `Webhook: ${row.eventType}`,
        description:
          row.status === 'sent'
            ? `Delivered (HTTP ${row.httpStatus ?? 'N/A'})`
            : `Failed: ${row.lastError ?? 'Unknown error'}`,
        data: {
          webhookUrl: '', // populated by the frontend from its own config
          eventType: row.eventType,
          eventId: row.eventId,
          status: row.status === 'sent' ? 'sent' : 'failed',
          httpStatus: row.httpStatus ?? null,
          errorMessage: row.lastError ?? null,
        } satisfies WebhookDeliveryFeedData,
      }));
    } catch (err) {
      this.logger.warn(`Webhook delivery fetch error: ${String(err)}`);
      return [];
    }
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function mapEscrowStatus(
  dbStatus: string,
): ContractActionFeedData['status'] {
  switch (dbStatus) {
    case 'completed':
    case 'resolved':
      return 'success';
    case 'pending':
    case 'awaiting_deposit':
      return 'pending';
    case 'failed':
    case 'irreconcilable':
      return 'failed';
    default:
      return 'pending';
  }
}
