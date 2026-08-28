import { Injectable } from "@nestjs/common";
import { throttlerConfig, RateLimitGroup } from "../config/rate-limit.config";
import { RateLimitStore, RateLimitConsumeResult } from "./rate-limit-store";
import { RateLimitStoreService } from "./rate-limit-store.service";

export interface RateLimitDecision extends RateLimitConsumeResult {
  /** Configured limit after applying any API-key multiplier. */
  limit: number;
  /** Window duration (ms) that the decision applies to. */
  windowMs: number;
}

export const RATE_LIMIT_API_KEY_MULTIPLIER = Number(
  process.env["RATE_LIMIT_API_KEY_MULTIPLIER"] ?? 6,
);

/**
 * Sliding-window rate limiter used by the global HTTP guard.
 *
 * Enforces both the "burst" (short window) and "sustained" (long window)
 * limits for a given rate-limit group. Both windows are sliding, so requests
 * spread across the burst window boundary cannot bypass the limit. An optional
 * per-window multiplier raises the limits for trusted API-key clients.
 */
@Injectable()
export class SlidingWindowRateLimiter {
  constructor(private readonly storeService: RateLimitStoreService) {}

  /**
   * The active backing store. Resolved per call so that an async Redis
   * connection can be adopted once ready, falling back to in-memory otherwise.
   */
  private get store(): RateLimitStore {
    return this.storeService.getStore();
  }

  async consume(
    group: RateLimitGroup,
    key: string,
    multiplier: number = 1,
  ): Promise<{ allowed: boolean; decision?: RateLimitDecision }> {
    const groupWindows = throttlerConfig.groups[group];
    if (!groupWindows) {
      // Unknown group — fail open.
      return { allowed: true };
    }

    const burst = groupWindows.burst;
    const sustained = groupWindows.sustained;

    const scaled = (limit: number) => Math.round(limit * multiplier);

    const burstResult = await this.safeConsume(
      `${group}:burst`,
      key,
      scaled(burst.limit),
      burst.ttlMs,
    );
    if (!burstResult.allowed) {
      return {
        allowed: false,
        decision: {
          ...burstResult,
          limit: scaled(burst.limit),
          windowMs: burst.ttlMs,
        },
      };
    }

    const sustainedResult = await this.safeConsume(
      `${group}:sustained`,
      key,
      scaled(sustained.limit),
      sustained.ttlMs,
    );

    return {
      allowed: sustainedResult.allowed,
      decision: sustainedResult.allowed
        ? {
            ...sustainedResult,
            limit: scaled(sustained.limit),
            windowMs: sustained.ttlMs,
          }
        : {
            ...sustainedResult,
            limit: scaled(sustained.limit),
            windowMs: sustained.ttlMs,
          },
    };
  }

  private async safeConsume(
    windowName: string,
    key: string,
    limit: number,
    windowMs: number,
  ): Promise<RateLimitConsumeResult> {
    const storeKey = `${windowName}:${key}`;
    try {
      return await this.store.consume(storeKey, limit, windowMs);
    } catch {
      // Store failure (e.g. Redis hiccup) — fail open and degrade gracefully.
      return { allowed: true, remaining: limit, resetAt: 0 };
    }
  }
}
