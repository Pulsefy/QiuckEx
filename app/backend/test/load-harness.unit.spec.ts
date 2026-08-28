import {
  evaluateThresholds,
  percentile,
  runLoad,
  ScenarioReport,
} from "../scripts/load/harness";

describe("load harness metrics", () => {
  it("calculates nearest-rank percentiles", () => {
    expect(percentile([40, 10, 30, 20], 50)).toBe(20);
    expect(percentile([40, 10, 30, 20], 95)).toBe(40);
    expect(percentile([], 99)).toBe(0);
  });

  it("reports threshold violations", () => {
    const report: ScenarioReport = {
      scenario: "link-create",
      requests: 10,
      successes: 8,
      errors: 2,
      errorRate: 0.2,
      throughput: 1,
      p50Ms: 20,
      p95Ms: 600,
      p99Ms: 1200,
    };

    expect(
      evaluateThresholds(report, {
        maxErrorRate: 0.01,
        maxP95Ms: 500,
        maxP99Ms: 1000,
        minThroughput: 2,
      }),
    ).toHaveLength(4);
  });

  it("runs a fixed number of requests at the configured concurrency", async () => {
    const requests: string[] = [];
    const report = await runLoad(
      {
        baseUrl: "http://localhost:4000",
        concurrency: 2,
        requests: 6,
        timeoutMs: 1000,
        scenarios: [
          {
            name: "link-create",
            method: "POST",
            path: "/links/metadata",
            body: { amount: 1, asset: "XLM" },
          },
        ],
      },
      async (input) => {
        requests.push(String(input));
        return new Response("{}", { status: 200 });
      },
    );

    expect(requests).toHaveLength(6);
    expect(report.totalRequests).toBe(6);
    expect(report.scenarios[0].successes).toBe(6);
    expect(report.scenarios[0].errors).toBe(0);
  });
});
