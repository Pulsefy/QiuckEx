/**
 * Simple in-memory sliding-window rate limiter.
 *
 * Limits notification dispatches to `maxPerWindow` per `windowMs`
 * per `(publicKey, channel)` key.  This runs in-process; for a
 * multi-instance deployment, swap the Map for a Redis ZSET.
 */
export class NotificationRateLimiter {
  private readonly windows = new Map<string, number[]>();

  constructor(
    /** Maximum notifications allowed within the window. */
    private readonly maxPerWindow: number = 10,
    /** Window duration in milliseconds (default 1 hour). */
    private readonly windowMs: number = 60 * 60 * 1_000,
  ) {}

  /**
   * Returns true if the notification should be allowed, false if rate-limited.
   * Calling this method is a side-effect: it records the attempt if allowed.
   */
  allow(publicKey: string, channel: string): boolean {
    const key = `${publicKey}:${channel}`;
    const now = Date.now();
    const cutoff = now - this.windowMs;

    const timestamps = (this.windows.get(key) ?? []).filter((t) => t > cutoff);

    if (timestamps.length >= this.maxPerWindow) {
      return false;
    }

    timestamps.push(now);
    this.windows.set(key, timestamps);
    return true;
  }

  /** For testing: clear all state. */
  reset(): void {
    this.windows.clear();
  }
}
