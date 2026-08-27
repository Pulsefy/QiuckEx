export interface RateLimitConsumeResult {
  /** Whether the request is allowed through. */
  allowed: boolean;
  /** Number of requests remaining within the current sliding window. */
  remaining: number;
  /** Unix timestamp (seconds) at which the window resets. */
  resetAt: number;
}

/**
 * Backend-agnostic store for the sliding-window rate limiter.
 *
 * Implementations may be in-memory (single instance) or Redis-backed
 * (multi-instance). Callers should treat a store failure as "degrade
 * gracefully" — see RateLimitStoreService.
 */
export interface RateLimitStore {
  /**
   * Records a request for `key` within a sliding window of `windowMs` across
   * the last `limit` calls. Returns whether the request is allowed.
   *
   * @param key    Identity (e.g. ip, api_key, user_id) to rate limit.
   * @param limit  Maximum requests allowed within the window.
   * @param windowMs Sliding window duration in milliseconds.
   */
  consume(key: string, limit: number, windowMs: number): Promise<RateLimitConsumeResult>;
}
