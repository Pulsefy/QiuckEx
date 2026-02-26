import { NotificationRateLimiter } from "../notification-rate-limiter";

describe("NotificationRateLimiter", () => {
  const KEY = "GPUBKEY";

  it("allows requests under the limit", () => {
    const rl = new NotificationRateLimiter(3, 60_000);
    expect(rl.allow(KEY, "email")).toBe(true);
    expect(rl.allow(KEY, "email")).toBe(true);
    expect(rl.allow(KEY, "email")).toBe(true);
  });

  it("blocks at the limit", () => {
    const rl = new NotificationRateLimiter(2, 60_000);
    rl.allow(KEY, "email");
    rl.allow(KEY, "email");
    expect(rl.allow(KEY, "email")).toBe(false);
  });

  it("independent buckets per (publicKey, channel)", () => {
    const rl = new NotificationRateLimiter(1, 60_000);
    expect(rl.allow(KEY, "email")).toBe(true);
    // email is now at limit, but push is not
    expect(rl.allow(KEY, "push")).toBe(true);
    // different user is also independent
    expect(rl.allow("OTHER", "email")).toBe(true);
  });

  it("resets after window expires", () => {
    jest.useFakeTimers();
    const rl = new NotificationRateLimiter(1, 1_000); // 1 second window
    rl.allow(KEY, "email"); // fills up
    expect(rl.allow(KEY, "email")).toBe(false);

    jest.advanceTimersByTime(1_100); // advance past window
    expect(rl.allow(KEY, "email")).toBe(true); // window reset
    jest.useRealTimers();
  });

  it("reset() clears all state", () => {
    const rl = new NotificationRateLimiter(1, 60_000);
    rl.allow(KEY, "email");
    rl.reset();
    expect(rl.allow(KEY, "email")).toBe(true);
  });
});
