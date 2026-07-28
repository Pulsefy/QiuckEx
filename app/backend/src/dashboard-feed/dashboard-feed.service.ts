import { Injectable, Logger } from '@nestjs/common';
import { DashboardFeedRepository } from './dashboard-feed.repository';
import type { GetFeedQueryDto } from './dto/get-feed.dto';
import type { FeedItem, FeedResponse } from './dashboard-feed.types';
import {
  decodeCursor,
  encodeCursor,
  clampLimit,
} from '../common/pagination/cursor.util';

@Injectable()
export class DashboardFeedService {
  private readonly logger = new Logger(DashboardFeedService.name);

  constructor(private readonly repository: DashboardFeedRepository) {}

  /**
   * Aggregate activity feed across all sources for the given address.
   *
   * Strategy: fetch from each enabled source independently (resilient to
   * partial failures), merge into a single sorted list, then paginate
   * deterministically using cursor-based pagination.
   */
  async getFeed(query: GetFeedQueryDto): Promise<FeedResponse> {
    const {
      address,
      kind,
      after,
      before,
      cursor,
      limit: rawLimit,
    } = query;

    const limit = clampLimit(rawLimit);
    const cursorPayload = cursor ? decodeCursor(cursor) : null;
    const failedSources: string[] = [];

    // When a cursor is provided, decode the timestamp for time-based filtering
    // across all sources. The cursor's pk field is the ISO timestamp.
    const effectiveAfter = cursorPayload?.pk ?? after;

    // ── Fetch from each source (or the requested kind only) ─────────────
    const allItems: FeedItem[] = [];

    const fetchSource = async (
      name: string,
      fetcher: () => Promise<FeedItem[]>,
    ) => {
      if (kind && kind !== name) return;
      try {
        const items = await fetcher();
        allItems.push(...items);
      } catch (err) {
        this.logger.warn(`DashboardFeed: ${name} source failed: ${err}`);
        failedSources.push(name);
      }
    };

    const fetchAll = address
      ? [
          fetchSource('payment', () =>
            this.repository.getPayments(address, effectiveAfter, before, limit + 1),
          ),
          fetchSource('refund', () =>
            this.repository.getRefunds(address, effectiveAfter, before, limit + 1),
          ),
          fetchSource('webhook_delivery', () =>
            this.repository.getWebhookDeliveries(address, effectiveAfter, before, limit + 1),
          ),
          fetchSource('notification', () =>
            this.repository.getNotifications(address, effectiveAfter, before, limit + 1),
          ),
          fetchSource('username_action', () =>
            this.repository.getUsernameActions(address, effectiveAfter, before, limit + 1),
          ),
          fetchSource('contract_event', () =>
            this.repository.getContractEvents(effectiveAfter, before, limit + 1),
          ),
        ]
      : [
          fetchSource('contract_event', () =>
            this.repository.getContractEvents(effectiveAfter, before, limit + 1),
          ),
        ];

    await Promise.all(fetchAll);

    // ── Deduplicate by id ───────────────────────────────────────────────
    const deduplicated = this.deduplicate(allItems);

    // ── Sort deterministically: timestamp DESC, then id DESC ────────────
    const sorted = deduplicated.sort((a, b) => {
      const tsDiff = new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      if (tsDiff !== 0) return tsDiff;
      return b.id.localeCompare(a.id);
    });

    // ── Apply cursor filter: skip items that were already returned ──────
    let filtered = sorted;
    if (cursorPayload) {
      filtered = sorted.filter((item) => {
        const tsMs = new Date(item.timestamp).getTime();
        const cursorTsMs = new Date(cursorPayload.pk).getTime();
        if (tsMs < cursorTsMs) return true;
        if (tsMs > cursorTsMs) return false;
        // Same timestamp: use id tiebreaker
        return item.id.localeCompare(cursorPayload.id) < 0;
      });
    }

    // ── Paginate ────────────────────────────────────────────────────────
    const hasMore = filtered.length > limit;
    const data = hasMore ? filtered.slice(0, limit) : filtered;

    let nextCursor: string | null = null;
    if (hasMore && data.length > 0) {
      const last = data[data.length - 1];
      nextCursor = encodeCursor({
        pk: last.timestamp,
        id: last.id,
      });
    }

    return {
      data,
      pagination: {
        next_cursor: nextCursor,
        has_more: hasMore,
        limit,
      },
      isPartial: failedSources.length > 0,
      failedSources,
    };
  }

  private deduplicate(items: FeedItem[]): FeedItem[] {
    const seen = new Set<string>();
    return items.filter((item) => {
      if (seen.has(item.id)) return false;
      seen.add(item.id);
      return true;
    });
  }
}
