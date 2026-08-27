import { Injectable, Logger } from "@nestjs/common";
import { RedisClient } from "../redis/redis-client";
import {
  RateLimitConsumeResult,
  RateLimitStore,
} from "./rate-limit-store";

/**
 * Redis-backed sliding-window rate limit store.
 *
 * Uses a Redis sorted set per rate-limit key, where each request's timestamp
 * is a member score. The sliding window is enforced by removing all entries
 * older than `windowMs` and counting the remainder — this avoids the classic
 * fixed-window boundary burst problem across multiple instances.
 *
 * If any Redis command fails (or the connection is unavailable), the wrapped
 * command is rejected so the caller can degrade gracefully to the in-memory
 * store.
 */
@Injectable()
export class RedisSlidingWindowStore implements RateLimitStore {
  private readonly logger = new Logger(RedisSlidingWindowStore.name);

  constructor(private readonly client: RedisClient) {}

  async consume(
    key: string,
    limit: number,
    windowMs: number,
  ): Promise<RateLimitConsumeResult> {
    if (!this.client.isConnected()) {
      await this.ensureConnection();
      if (!this.client.isConnected()) {
        throw new Error("Redis unavailable");
      }
    }

    const redisKey = `rate_limit:${key}`;
    const now = Date.now();
    const cutoff = now - windowMs;

    await this.client.zRemRangeByScore(redisKey, 0, cutoff);
    const count = await this.client.zCard(redisKey);

    const remaining = Math.max(0, limit - count);

    if (count >= limit) {
      const entries = await this.client.zRange(redisKey, 0, 0);
      return {
        allowed: false,
        remaining: 0,
        resetAt: this.computeResetAt(entries, now, windowMs),
      };
    }

    const member = `${now}:${Math.random().toString(36).slice(2)}`;
    await this.client.zAdd(redisKey, now, member);
    await this.client.expire(redisKey, Math.ceil(windowMs / 1000) || 1);

    return {
      allowed: true,
      remaining: limit - (count + 1),
      resetAt: Math.floor((now + windowMs) / 1000),
    };
  }

  private computeResetAt(
    entries: string[],
    now: number,
    windowMs: number,
  ): number {
    if (entries && entries.length > 0) {
      // WITHSCORES returns [member, score, ...]; score is at index 1.
      const score = Number(entries[1] ?? entries[0]);
      if (!Number.isNaN(score)) {
        const waitMs = windowMs - (now - score);
        return Math.floor((now + (waitMs > 0 ? waitMs : 0)) / 1000);
      }
    }
    return Math.floor((now + windowMs) / 1000);
  }

  private async ensureConnection(): Promise<void> {
    try {
      await this.client.connect();
    } catch (err) {
      this.logger.warn(`Could not connect to Redis: ${(err as Error).message}`);
    }
  }
}
