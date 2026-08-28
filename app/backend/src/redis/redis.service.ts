import { Injectable, Logger, OnModuleDestroy } from "@nestjs/common";
import Redis from "ioredis";

import { AppConfigService } from "../config";

/**
 * Small Redis wrapper used for cross-cutting concerns such as health checks,
 * stale-data caching and delivery-id deduplication.
 *
 * It is intentionally resilient: when Redis is not configured (or the connection
 * is unavailable) every operation degrades gracefully to a no-op for writes /
 * a "miss" for reads, so the rest of the application keeps working with its
 * in-memory fallbacks.
 */
@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  private client: Redis | null = null;

  constructor(private readonly appConfig: AppConfigService) {
    const url = this.appConfig.redisUrl;
    if (!url) {
      this.logger.warn(
        "REDIS_URL not configured — Redis-backed features will use in-memory fallbacks.",
      );
      return;
    }

    try {
      this.client = new Redis(url, {
        lazyConnect: true,
        maxRetriesPerRequest: 1,
        enableOfflineQueue: false,
        retryStrategy: (times) => (times > 3 ? null : Math.min(times * 200, 1000)),
      });

      this.client.on("error", (err) => {
        this.logger.warn(`Redis connection error: ${err.message}`);
      });

      // Best-effort connect; failures are handled gracefully by callers.
      this.client.connect().catch((err) => {
        this.logger.warn(`Redis connect failed: ${err?.message}`);
      });
    } catch (err) {
      this.logger.warn(`Failed to initialise Redis client: ${err}`);
      this.client = null;
    }
  }

  get isConfigured(): boolean {
    return !!this.client;
  }

  get isReady(): boolean {
    return !!this.client && this.client.status === "ready";
  }

  /** Ping the Redis server. Returns false when not configured / unreachable. */
  async ping(): Promise<boolean> {
    if (!this.client) return false;
    try {
      const reply = await this.client.ping();
      return reply === "PONG";
    } catch {
      return false;
    }
  }

  async get(key: string): Promise<string | null> {
    if (!this.client) return null;
    try {
      return await this.client.get(key);
    } catch (err) {
      this.logger.debug(`Redis get failed for ${key}: ${err}`);
      return null;
    }
  }

  async set(key: string, value: string, ttlMs?: number): Promise<void> {
    if (!this.client) return;
    try {
      if (ttlMs && ttlMs > 0) {
        await this.client.set(key, value, "PX", ttlMs);
      } else {
        await this.client.set(key, value);
      }
    } catch (err) {
      this.logger.debug(`Redis set failed for ${key}: ${err}`);
    }
  }

  async del(key: string): Promise<void> {
    if (!this.client) return;
    try {
      await this.client.del(key);
    } catch (err) {
      this.logger.debug(`Redis del failed for ${key}: ${err}`);
    }
  }

  /**
   * Atomically set a key only if it does not already exist (used for
   * idempotent delivery-id deduplication). Returns true when this call
   * acquired the lock / set the value, false when the key already exists.
   */
  async setNx(key: string, value: string, ttlMs?: number): Promise<boolean> {
    if (!this.client) {
      // Without Redis we cannot guarantee cross-instance dedup; treat every
      // call as a fresh (non-duplicate) attempt so delivery is not lost.
      return true;
    }
    try {
      const result =
        ttlMs && ttlMs > 0
          ? await this.client.set(key, value, "PX", ttlMs, "NX")
          : await this.client.set(key, value, "NX");
      return result === "OK";
    } catch (err) {
      this.logger.debug(`Redis setNx failed for ${key}: ${err}`);
      return true;
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.client) {
      try {
        this.client.disconnect();
      } catch {
        // ignore
      }
      this.client = null;
    }
  }
}
