import { resolve } from "node:path";
import {
  LoadConfig,
  ScenarioConfig,
  Thresholds,
  formatPercent,
  readJsonFile,
  runLoad,
} from "./harness";

const defaults: Record<string, string> = {
  BASE_URL: "http://localhost:4000",
  CONCURRENCY: "10",
  DURATION_SECONDS: "30",
  TIMEOUT_MS: "5000",
  USERNAME: "load-test-user",
  AMOUNT: "1",
  ASSET: "XLM",
  MEMO: "load-test",
  TX_HASH: "",
};

function env(name: string): string {
  return process.env[name] || defaults[name] || "";
}

function scenarioConfig(): ScenarioConfig[] {
  const username = encodeURIComponent(env("USERNAME"));
  const amount = encodeURIComponent(env("AMOUNT"));
  const asset = encodeURIComponent(env("ASSET"));
  const memo = encodeURIComponent(env("MEMO"));
  const txHash = encodeURIComponent(env("TX_HASH"));
  return [
    {
      name: "link-create",
      method: "POST",
      path: "/links/metadata",
      body: { amount: Number(env("AMOUNT")), asset: env("ASSET"), memo: env("MEMO") },
    },
    {
      name: "payment-page-read",
      method: "GET",
      path: `/payment-links/status?username=${username}&amount=${amount}&asset=${asset}&memo=${memo}`,
    },
    {
      name: "receipt-read",
      method: "GET",
      path: `/v1/receipts/tx/${txHash}?operationIndex=0`,
    },
  ];
}

async function main(): Promise<void> {
  const baselinePath = process.env.BASELINE_FILE || resolve(__dirname, "baseline.json");
  const thresholds = await readJsonFile<Partial<Record<string, Thresholds>>>(baselinePath);
  const config: LoadConfig = {
    baseUrl: env("BASE_URL"),
    concurrency: Number(env("CONCURRENCY")),
    durationSeconds: process.env.REQUESTS ? undefined : Number(env("DURATION_SECONDS")),
    requests: process.env.REQUESTS ? Number(process.env.REQUESTS) : undefined,
    timeoutMs: Number(env("TIMEOUT_MS")),
    scenarios: scenarioConfig(),
    thresholds: thresholds as LoadConfig["thresholds"],
    headers: process.env.API_KEY ? { "X-API-Key": process.env.API_KEY } : undefined,
  };

  const report = await runLoad(config);
  console.log(JSON.stringify(report, null, 2));
  for (const scenario of report.scenarios) {
    console.log(
      `${scenario.scenario}: ${scenario.throughput} req/s, ` +
        `p50/p95/p99 ${scenario.p50Ms}/${scenario.p95Ms}/${scenario.p99Ms}ms, ` +
        `errors ${formatPercent(scenario.errorRate)}`,
    );
  }
  if (report.failures.length > 0) {
    console.error("Load thresholds failed:");
    report.failures.forEach((failure) => console.error(`- ${failure}`));
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
