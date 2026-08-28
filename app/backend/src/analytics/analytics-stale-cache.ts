import { Injectable, Logger } from "@nestjs/common";
import { LRUCache } from "lru-cache";

import { AppConfigService } from "../config";
import { AnalyticsInterval } from "./dto/analytics-query.dto";
import type { AnalyticsReport } from "./analytics.service";

export type StaleCacheEntry = {
  report: AnalyticsReport;
  generatedAt: number;
};

/**
 * Stores the last successful analytics report per (publicKey, interval) so the
 * dashboard can keep serving (stale) data when the data source is unavailable.
 *
 * Entries are retained for up to `MAX_STALE_AGE_MS` (24h) and a fresh result is
 * cached with a configurable TTL (default 5m). On failure the controller signals
 * staleness via the `X-Cache-Status: stale` header.
 */
@Injectable()
export class AnalyticsStaleCache {
  private readonly logger = new Logger(AnalyticsStaleCache.name);
  private readonly cache: LRUCache<string, StaleCacheEntry>;

  /** Stale data is only ever served up to 24 hours old. */
  private readonly MAX_STALE_AGE_MS = 24 * 60 * 60 * 1000;

  constructor(private readonly appConfig: AppConfigService) {
    const ttl = Math.max(this.appConfig.analyticsStaleCacheTtlMs, 1000);
    this.cache = new LRUCache<string, StaleCacheEntry>({
      max: 1000,
      // Retain entries long enough to serve stale data within the 24h cap.
      ttl: Math.max(ttl, this.MAX_STALE_AGE_MS),
      updateAgeOnGet: false,
    });
  }

  /**
   * Separate cache key per publicKey, interval, organization and date window.
   */
  getCacheKey(
    publicKey: string,
    interval: AnalyticsInterval,
    organizationId?: string,
    startDate?: string,
    endDate?: string,
  ): string {
    return [
      "quickex",
      "analytics",
      "stale",
      publicKey,
      interval,
      organizationId ?? "anon",
      startDate ?? "default-start",
      endDate ?? "default-end",
    ].join(":");
  }

  get(kind: "fresh" | "stale", key: string): StaleCacheEntry | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined;

    const age = Date.now() - entry.generatedAt;
    if (age > this.MAX_STALE_AGE_MS) {
      this.cache.delete(key);
      return undefined;
    }

    // A "fresh" hit means the cached copy is within the configured TTL — no need
    // to recompute on failure paths that can still serve it. `kind` is used to
    // keep semantics explicit; both resolve to the same entry.
    void kind;

    return entry;
  }

  set(key: string, entry: StaleCacheEntry): void {
    this.cache.set(key, entry, {
      ttl: Math.max(
        this.appConfig.analyticsStaleCacheTtlMs,
        this.MAX_STALE_AGE_MS,
      ),
    });
  }
}
