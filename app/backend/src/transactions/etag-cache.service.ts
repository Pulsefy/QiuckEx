import { Injectable, Logger } from "@nestjs/common";
import { createHash } from "crypto";
import { LRUCache } from "lru-cache";

import { MetricsService } from "../metrics/metrics.service";

export const COMPOSE_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
export const SIMULATE_CACHE_TTL_MS = 60 * 1000; // 1 minute

export type EtagCacheRoute = "compose" | "simulate";

@Injectable()
export class EtagCacheService {
  private readonly logger = new Logger(EtagCacheService.name);
  private readonly cache: LRUCache<string, unknown>;

  constructor(private readonly metrics: MetricsService) {
    this.cache = new LRUCache<string, unknown>({
      max: 1000,
      ttl: COMPOSE_CACHE_TTL_MS,
      // Keep entries sticky so a 304 can be returned for the whole TTL window
      // even after an occasional access — recomputation only happens on eviction.
      updateAgeOnGet: false,
    });
  }

  /**
   * Cache key is the SHA-256 of the serialized request payload as required by
   * the acceptance criteria. Identical requests collapse onto the same key.
   */
  computeCacheKey(payload: unknown): string {
    const normalized = JSON.stringify(payload ?? {});
    return createHash("sha256").update(normalized).digest("hex");
  }

  /**
   * Look up a cached response. Records hit/miss so the metrics endpoint can
   * surface the ETag cache hit ratio per route.
   */
  get(route: EtagCacheRoute, etag: string): unknown | undefined {
    const hit = this.cache.get(etag);
    this.metrics.recordEtagCacheResult(route, hit ? "hit" : "miss");
    if (hit) {
      this.logger.debug(`ETag cache hit [${route}] ${etag}`);
    }
    return hit;
  }

  /**
   * Store a response under an ETag with a route-specific TTL.
   */
  set(route: EtagCacheRoute, etag: string, value: unknown): void {
    const ttlMs =
      route === "compose" ? COMPOSE_CACHE_TTL_MS : SIMULATE_CACHE_TTL_MS;
    this.cache.set(etag, value, { ttl: ttlMs });
  }
}
