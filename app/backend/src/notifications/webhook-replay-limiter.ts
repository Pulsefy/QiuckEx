/**
 * In-process safeguards against webhook replay storms.
 *
 * Two independent gates:
 *  - Per-event cooldown: same (webhook, event) cannot be replayed within cooldownMs.
 *  - Per-webhook quota: max replays per webhook within quotaWindowMs.
 *
 * For multi-instance deployments, swap Maps for Redis keys.
 */
export class WebhookReplayLimiter {
  private readonly eventLastReplay = new Map<string, number>();
  private readonly webhookReplayTimestamps = new Map<string, number[]>();

  constructor(
    private readonly eventCooldownMs: number = 30_000,
    private readonly quotaPerWindow: number = 20,
    private readonly quotaWindowMs: number = 60 * 60 * 1_000,
  ) {}

  /**
   * Returns null when allowed; otherwise a rejection reason string.
   * Records the attempt when allowed (side-effect).
   */
  checkAndRecord(
    webhookId: string,
    eventType: string,
    eventId: string,
  ): string | null {
    const eventKey = `${webhookId}:${eventType}:${eventId}`;
    const now = Date.now();

    const lastEventReplay = this.eventLastReplay.get(eventKey);
    if (
      lastEventReplay !== undefined &&
      now - lastEventReplay < this.eventCooldownMs
    ) {
      const retryAfterSeconds = Math.ceil(
        (this.eventCooldownMs - (now - lastEventReplay)) / 1_000,
      );
      return `Event replay cooldown active. Retry after ${retryAfterSeconds} seconds.`;
    }

    const cutoff = now - this.quotaWindowMs;
    const webhookTimestamps = (this.webhookReplayTimestamps.get(webhookId) ?? [])
      .filter((t) => t > cutoff);

    if (webhookTimestamps.length >= this.quotaPerWindow) {
      const oldest = webhookTimestamps[0] ?? now;
      const retryAfterSeconds = Math.ceil(
        (this.quotaWindowMs - (now - oldest)) / 1_000,
      );
      return `Webhook replay quota exceeded. Retry after ${retryAfterSeconds} seconds.`;
    }

    webhookTimestamps.push(now);
    this.webhookReplayTimestamps.set(webhookId, webhookTimestamps);
    this.eventLastReplay.set(eventKey, now);

    return null;
  }

  /** For testing: clear all state. */
  reset(): void {
    this.eventLastReplay.clear();
    this.webhookReplayTimestamps.clear();
  }
}
