import { WebhookReplayLimiter } from "../webhook-replay-limiter";

describe("WebhookReplayLimiter", () => {
  const WEBHOOK_ID = "webhook-1";
  const EVENT_TYPE = "payment.received";
  const EVENT_ID = "tx_abc";

  it("allows replays under quota and outside cooldown", () => {
    const limiter = new WebhookReplayLimiter(1_000, 5, 60_000);
    expect(limiter.checkAndRecord(WEBHOOK_ID, EVENT_TYPE, EVENT_ID)).toBeNull();
  });

  it("blocks duplicate replay within event cooldown (idempotency)", () => {
    const limiter = new WebhookReplayLimiter(5_000, 10, 60_000);
    expect(limiter.checkAndRecord(WEBHOOK_ID, EVENT_TYPE, EVENT_ID)).toBeNull();
    const reason = limiter.checkAndRecord(WEBHOOK_ID, EVENT_TYPE, EVENT_ID);
    expect(reason).toMatch(/cooldown/i);
  });

  it("allows replay of different events on same webhook during cooldown", () => {
    const limiter = new WebhookReplayLimiter(5_000, 10, 60_000);
    limiter.checkAndRecord(WEBHOOK_ID, EVENT_TYPE, "tx_one");
    expect(
      limiter.checkAndRecord(WEBHOOK_ID, EVENT_TYPE, "tx_two"),
    ).toBeNull();
  });

  it("blocks when webhook hourly quota is exceeded (abuse protection)", () => {
    const limiter = new WebhookReplayLimiter(0, 2, 60_000);
    expect(limiter.checkAndRecord(WEBHOOK_ID, EVENT_TYPE, "tx_1")).toBeNull();
    expect(limiter.checkAndRecord(WEBHOOK_ID, EVENT_TYPE, "tx_2")).toBeNull();
    const reason = limiter.checkAndRecord(WEBHOOK_ID, EVENT_TYPE, "tx_3");
    expect(reason).toMatch(/quota/i);
  });

  it("reset clears state", () => {
    const limiter = new WebhookReplayLimiter(5_000, 1, 60_000);
    limiter.checkAndRecord(WEBHOOK_ID, EVENT_TYPE, EVENT_ID);
    limiter.reset();
    expect(
      limiter.checkAndRecord(WEBHOOK_ID, EVENT_TYPE, EVENT_ID),
    ).toBeNull();
  });
});
