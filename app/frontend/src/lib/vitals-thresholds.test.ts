import { describe, expect, it } from "vitest";
import { classify, evaluateVitals } from "./vitals-thresholds";

describe("vitals-thresholds (FE-66)", () => {
  it("classifies each metric against web.dev thresholds", () => {
    expect(classify("LCP", 2000)).toBe("good");
    expect(classify("LCP", 3000)).toBe("needs-improvement");
    expect(classify("LCP", 5000)).toBe("poor");
    expect(classify("CLS", 0.05)).toBe("good");
    expect(classify("CLS", 0.3)).toBe("poor");
    expect(classify("INP", 150)).toBe("good");
    expect(classify("INP", 600)).toBe("poor");
  });

  it("fails the build when a metric is poor (default policy)", () => {
    const report = evaluateVitals([
      { page: "/pay", metric: "LCP", value: 4500 },
    ]);
    expect(report.failed).toBe(true);
    expect(report.results[0].regressed).toBe(true);
  });

  it("passes when all metrics are within budget", () => {
    const report = evaluateVitals([
      { page: "/pay", metric: "LCP", value: 2000 },
      { page: "/receipt", metric: "CLS", value: 0.05 },
      { page: "/dashboard", metric: "INP", value: 120 },
    ]);
    expect(report.failed).toBe(false);
  });

  it("computes a delta against the base run", () => {
    const report = evaluateVitals(
      [{ page: "/pay", metric: "LCP", value: 2600 }],
      { failOnPoor: false },
      [{ page: "/pay", metric: "LCP", value: 2400 }],
    );
    expect(report.results[0].delta).toBe(200);
  });

  it("can be configured not to fail on poor (flag-only policy)", () => {
    const report = evaluateVitals(
      [{ page: "/pay", metric: "LCP", value: 9000 }],
      { failOnPoor: false },
    );
    expect(report.failed).toBe(false);
    expect(report.results[0].status).toBe("poor");
  });
});
