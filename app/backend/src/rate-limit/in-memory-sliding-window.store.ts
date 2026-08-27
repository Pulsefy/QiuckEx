import { Injectable } from "@nestjs/common";
import {
  RateLimitConsumeResult,
  RateLimitStore,
} from "./rate-limit-store";

interface WindowEntry {
  /** Tracks the sliding window per key: member id -> timestamp. */
  timestamps: number[];
}

/**
 * In-memory sliding-window rate limit store.
 *
 * Unlike a fixed-window limiter, the sliding window prunes expired entries
 * continuously so bursts at window boundaries cannot bypass the limit. On a
 * single instance this store is fully functional; it also serves as the
 * graceful fallback when Redis is unavailable (see RateLimitStoreService).
 */
@Injectable()
export class InMemorySlidingWindowStore implements RateLimitStore {
  private readonly windows = new Map<string, WindowEntry>();
  private readonly ttlMs = 5 * 60 * 1000;

  async consume(
    key: string,
    limit: number,
    windowMs: number,
  ): Promise<RateLimitConsumeResult> {
    const now = Date.now();
    const cutoff = now - windowMs;

    let entry = this.windows.get(key);
    if (!entry) {
      entry = { timestamps: [] };
      this.windows.set(key, entry);
    }

    // Prune entries that have fallen outside the sliding window.
    const timestamps = entry.timestamps.filter((t) => t > cutoff);
    entry.timestamps = timestamps;
    this.windows.set(key, entry);

    const remaining = Math.max(0, limit - timestamps.length);

    if (timestamps.length >= limit) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: this.nextResetAt(timestamps, windowMs),
      };
    }

    timestamps.push(now);
    this.windows.set(key, entry);

    return {
      allowed: true,
      remaining: limit - timestamps.length,
      resetAt: this.nextResetAt(timestamps, windowMs),
    };
  }

  /**
   * Earliest timestamp after which a new request becomes available.
   */
  private nextResetAt(timestamps: number[], windowMs: number): number {
    const now = Date.now();
    if (timestamps.length > 0) {
      // The oldest request expires (now - windowMs + oldest) seconds from now.
      const oldest = Math.min(...timestamps);
      const waitMs = windowMs - (now - oldest);
      return Math.floor((now + (waitMs > 0 ? waitMs : 0)) / 1000);
    }
    return Math.floor((now + windowMs) / 1000);
  }

  /**
   * Prevent unbounded growth for idle keys. Called periodically by the module.
   */
  prune(): void {
    const now = Date.now();
    for (const [key, entry] of this.windows) {
      entry.timestamps = entry.timestamps.filter((t) => t > now - this.ttlMs);
      if (entry.timestamps.length === 0) {
        this.windows.delete(key);
      }
    }
  }

  size(): number {
    return this.windows.size;
  }

  clear(): void {
    this.windows.clear();
  }
}
