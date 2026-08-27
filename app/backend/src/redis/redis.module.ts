import { Global, Module } from "@nestjs/common";
import { RedisCacheService } from "./redis-cache.service";

/**
 * Global Redis integration. Provides RedisCacheService, which degrades
 * gracefully to an in-memory cache when Redis is unavailable.
 */
@Global()
@Module({
  providers: [RedisCacheService],
  exports: [RedisCacheService],
})
export class RedisModule {}
