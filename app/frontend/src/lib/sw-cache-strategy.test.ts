import { describe, expect, it } from "vitest";
import {
  CACHE_NAMES,
  CACHE_VERSION,
  chooseStrategy,
  isPaymentCritical,
  OFFLINE_FALLBACK_URL,
} from "./sw-cache-strategy";

describe("sw-cache-strategy (FE-64)", () => {
  it("never caches payment-critical API reads", () => {
    expect(chooseStrategy("/api/payments/123")).toBe("network-only");
    expect(chooseStrategy("/api/links/abc")).toBe("network-only");
    expect(chooseStrategy("/api/transactions")).toBe("network-only");
    expect(isPaymentCritical("/api/receipts/9")).toBe(true);
  });

  it("uses network-only for any mutation regardless of path", () => {
    expect(chooseStrategy("/_next/static/x.js", "POST")).toBe("network-only");
    expect(chooseStrategy("/anything", "DELETE")).toBe("network-only");
  });

  it("uses network-first for non-critical API reads", () => {
    expect(chooseStrategy("/api/usernames/alice")).toBe("network-first");
  });

  it("uses cache-first for hashed static assets", () => {
    expect(chooseStrategy("/_next/static/chunks/main.js")).toBe("cache-first");
    expect(chooseStrategy("/logo.svg")).toBe("cache-first");
    expect(chooseStrategy("/fonts/inter.woff2")).toBe("cache-first");
  });

  it("falls back to the offline route for navigations", () => {
    expect(chooseStrategy("/dashboard", "GET", "navigate")).toBe(
      "offline-fallback",
    );
    expect(OFFLINE_FALLBACK_URL).toBe("/offline");
  });

  it("versions cache names so a deploy invalidates old entries", () => {
    expect(CACHE_NAMES.static).toContain(CACHE_VERSION);
    expect(CACHE_NAMES.shell).toContain(CACHE_VERSION);
    expect(CACHE_NAMES.api).toContain(CACHE_VERSION);
  });
});
