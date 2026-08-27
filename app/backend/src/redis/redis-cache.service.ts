import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { RedisClient } from "./redis-client";

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

/**
 * Small distributed cache backed by Redis with a graceful in-memory fallback.
 *
 * Used by the Horizon circuit-breaker to serve cached data while the remote
 * service is declared unavailable. If Redis is not configured or unreachable,
 * the cache degrades to an in-process Map (TTL honored).
 */
@Injectable()
export class RedisCacheService {
  private readonly logger = new Logger(RedisCacheService.name);
  private readonly memory = new Map<string, CacheEntry<string>>();
  private readonly client: RedisClient | null = null;
  private redisAvailable = false;

  constructor(configService: ConfigService) {
    const redisUrl = configService.get<string>("REDIS_URL");
    if (redisUrl) {
      const client = new RedisClient(redisUrl);
      this.client = client;
      client.connect().then((ok) => {
        this.redisAvailable = ok;
        if (ok) {
          this.logger.log("Redis cache connected");
        } else {
          this.logger.warn("Redis cache unavailable — using in-memory cache");
        }
      });
    }
  }

  async get<T>(key: string): Promise<T | undefined> {
    if (this.redisAvailable && this.client) {
      try {
        const raw = await this.client.get(key);
        if (raw === null) return undefined;
        return JSON.parse(raw) as T;
      } catch {
        // Fall through to in-memory on Redis error.
      }
    }

    const entry = this.memory.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= Date.now()) {
      this.memory.delete(key);
      return undefined;
    }
    return JSON.parse(entry.value) as T;
  }

  async set<T>(key: string, value: T, ttlMs: number): Promise<void> {
    const payload = JSON.stringify(value);
    const ttlSeconds = Math.ceil(ttlMs / 1000) || 1;

    if (this.redisAvailable && this.client) {
      try {
        await this.client.set(key, payload, ttlSeconds);
        // If the write fails we silently fall back to memory below.
      } catch {
        // fall through
      }
    }

    this.memory.set(key, {
      value: payload,
      expiresAt: Date.now() + ttlMs,
    });
  }

  async del(key: string): Promise<void> {
    if (this.redisAvailable && this.client) {
      try {
        await this.client.del(key);
      } catch {
        // ignore
      }
    }
    this.memory.delete(key);
  }

  isRedisBacked(): boolean {
    return this.redisAvailable;
  }
}
