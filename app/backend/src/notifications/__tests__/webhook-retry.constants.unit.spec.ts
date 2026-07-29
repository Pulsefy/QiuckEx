import {
  computeWebhookNextRetryAt,
  WEBHOOK_MAX_DELIVERY_ATTEMPTS,
  WEBHOOK_RETRY_DELAYS_MS,
} from "../webhook-retry.constants";

describe("webhook-retry.constants", () => {
  it("defines max attempts as initial + retry delays", () => {
    expect(WEBHOOK_MAX_DELIVERY_ATTEMPTS).toBe(
      WEBHOOK_RETRY_DELAYS_MS.length + 1,
    );
  });

  it("computes next retry from last failure and attempt count", () => {
    const lastFailed = new Date("2024-01-15T10:00:00Z");
    const next = computeWebhookNextRetryAt(1, lastFailed);
    expect(next?.toISOString()).toBe(
      new Date(lastFailed.getTime() + WEBHOOK_RETRY_DELAYS_MS[0]).toISOString(),
    );
  });

  it("returns null when attempts exhausted", () => {
    expect(
      computeWebhookNextRetryAt(
        WEBHOOK_MAX_DELIVERY_ATTEMPTS,
        new Date(),
      ),
    ).toBeNull();
  });
});
