import { Global, Module } from "@nestjs/common";

import { RedisService } from "./redis.service";

/**
 * Shared, optional Redis wrapper. Marked global so any module can inject
 * RedisService. When REDIS_URL is not configured, RedisService degrades to a
 * graceful no-op / in-memory fallback.
 */
@Global()
@Module({
  providers: [RedisService],
  exports: [RedisService],
})
export class RedisModule {}
