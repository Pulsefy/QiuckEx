import { describe, expect, it } from "vitest";

import { getSectionTone, getSeverityTone, summarizeReport } from "./testnetHealth.utils";

describe("testnet health utils", () => {
  it("maps blocker severities to scan-friendly classes", () => {
    expect(getSeverityTone("critical")).toContain("danger");
    expect(getSeverityTone("warning")).toContain("warning");
    expect(getSeverityTone("info")).toContain("info");
  });

  it("summarizes release readiness from the backend report", () => {
    const summary = summarizeReport({
      releaseReady: false,
      overallStatus: "blocked",
      summary: { critical: 2, warning: 1, info: 0 },
      sections: {
        smoke: { status: "fail", ready: false, checks: [], passed: 0, failed: 1 },
        registry: { status: "fail", network: "testnet", authoritative: false, version: 2, activeContracts: 0, expectedContracts: ["quickex"], missingContracts: ["quickex"] },
        lag: { status: "fail", currentNetworkLedger: 1000, lastIndexedLedger: 100, lagLedgers: 900, isLagging: true, isBlocking: true, thresholdLedgers: 100 },
        environment: { status: "warning", checks: [], passed: 0, failed: 0, warnings: 1 },
      },
    } as never);

    expect(summary.overall).toBe("Blocked");
    expect(summary.blocks).toBe(3);
    expect(getSectionTone("fail")).toContain("danger");
  });
});
