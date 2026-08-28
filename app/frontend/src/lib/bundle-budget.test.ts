import { describe, expect, it } from "vitest";
import {
  evaluateBudgets,
  formatBytes,
  formatDelta,
} from "./bundle-budget";

describe("bundle-budget (FE-65)", () => {
  it("flags a route that exceeds its budget", () => {
    const report = evaluateBudgets(
      [{ route: "/generator", bytes: 300_000 }],
      [{ route: "/generator", maxBytes: 250_000 }],
    );
    expect(report.failed).toBe(true);
    expect(report.results[0].over).toBe(true);
  });

  it("allows a route within budget plus tolerance", () => {
    const report = evaluateBudgets(
      [{ route: "/generator", bytes: 260_000 }],
      [{ route: "/generator", maxBytes: 250_000 }],
      0.05, // 5% tolerance → limit 262,500
    );
    expect(report.failed).toBe(false);
    expect(report.results[0].over).toBe(false);
    expect(report.results[0].limit).toBe(262_500);
  });

  it("computes a delta against the base branch", () => {
    const report = evaluateBudgets(
      [{ route: "/pay", bytes: 120_000 }],
      [{ route: "/pay", maxBytes: 200_000 }],
      0,
      [{ route: "/pay", bytes: 108_000 }],
    );
    expect(report.results[0].deltaBytes).toBe(12_000);
  });

  it("treats routes without a configured budget as informational", () => {
    const report = evaluateBudgets(
      [{ route: "/new-route", bytes: 999_999 }],
      [],
    );
    expect(report.failed).toBe(false);
    expect(report.results[0].maxBytes).toBeNull();
  });

  it("formats bytes and signed deltas", () => {
    expect(formatBytes(131_072)).toBe("128.0 KB");
    expect(formatDelta(12_288)).toBe("+12.0 KB");
    expect(formatDelta(-3_072)).toBe("−3.0 KB");
    expect(formatDelta(null)).toBe("—");
  });
});
