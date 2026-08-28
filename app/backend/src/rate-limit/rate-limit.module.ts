import { Global, Module } from "@nestjs/common";
import { MetricsModule } from "../metrics/metrics.module";
import { InMemorySlidingWindowStore } from "./in-memory-sliding-window.store";
import { RateLimitStoreService } from "./rate-limit-store.service";
import { RedisSlidingWindowRateLimitGuard } from "./redis-sliding-window-rate-limit.guard";
import { SlidingWindowRateLimiter } from "./sliding-window-rate-limiter.service";

/**
 * Redis-backed sliding-window rate limiting.
 *
 * Provides the global RedisSlidingWindowRateLimitGuard and a
 * RateLimitStoreService that degrades gracefully to an in-memory store when
 * Redis is unavailable.
 */
@Global()
@Module({
  imports: [MetricsModule],
  providers: [
    InMemorySlidingWindowStore,
    RateLimitStoreService,
    RedisSlidingWindowRateLimitGuard,
    SlidingWindowRateLimiter,
  ],
  exports: [
    RateLimitStoreService,
    RedisSlidingWindowRateLimitGuard,
    SlidingWindowRateLimiter,
  ],
})
export class RateLimitModule {}
