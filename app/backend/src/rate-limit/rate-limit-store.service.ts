import { Injectable, Logger, OnModuleDestroy } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { RedisClient } from "../redis/redis-client";
import { InMemorySlidingWindowStore } from "./in-memory-sliding-window.store";
import { RedisSlidingWindowStore } from "./redis-sliding-window.store";
import { RateLimitStore } from "./rate-limit-store";

/**
 * Selects the active backing store for the sliding-window rate limiter.
 *
 * Prefers Redis when:
 *   - RATE_LIMIT_REDIS_ENABLED is not explicitly "false", and
 *   - REDIS_URL is configured, and
 *   - a PING to Redis succeeds.
 *
 * Otherwise it degrades gracefully to the in-memory store so rate limiting
 * continues to work even when Redis is unavailable.
 */
@Injectable()
export class RateLimitStoreService implements OnModuleDestroy {
  private readonly logger = new Logger(RateLimitStoreService.name);
  private store: RateLimitStore;
  private redisClient: RedisClient | null = null;

  constructor(private readonly configService: ConfigService) {
    // Always start with the in-memory store so rate limiting is functional
    // immediately and degrades gracefully if Redis is absent or fails.
    this.store = new InMemorySlidingWindowStore();

    const redisEnabled =
      this.configService.get<string>("RATE_LIMIT_REDIS_ENABLED") !== "false";
    const redisUrl = this.configService.get<string>("REDIS_URL");

    if (redisEnabled && redisUrl) {
      const client = new RedisClient(redisUrl);
      this.redisClient = client;

      client.connect().then((ok) => {
        if (ok) {
          this.logger.log("Rate limiter using Redis sliding-window store");
          this.store = new RedisSlidingWindowStore(client);
        } else {
          this.logger.warn(
            "Redis unavailable — rate limiter degrading to in-memory store",
          );
        }
      });
    } else {
      this.logger.log(
        "REDIS_URL not configured — rate limiter using in-memory store",
      );
    }
  }

  getStore(): RateLimitStore {
    return this.store;
  }

  isRedisBacked(): boolean {
    return this.redisClient !== null && this.redisClient.isConnected();
  }

  onModuleDestroy(): void {
    this.redisClient?.disconnect();
  }
}
