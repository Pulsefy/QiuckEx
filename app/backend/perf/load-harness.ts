import { readFile, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { resolve } from "node:path";

type ScenarioName = "link-creation" | "payment-page-read" | "receipt-read";

interface ScenarioConfig {
  minThroughput: number;
  maxP95Ms: number;
  maxP99Ms: number;
  maxErrorRate: number;
}

interface Sample {
  durationMs: number;
  status: number | null;
  error?: string;
}

interface ScenarioResult extends ScenarioConfig {
  name: ScenarioName;
  requests: number;
  successes: number;
  errors: number;
  errorRate: number;
  throughput: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
  statuses: Record<string, number>;
}

interface Options {
  baseUrl: string;
  concurrency: number;
  durationSeconds: number;
  timeoutMs: number;
  warmupSeconds: number;
  scenarios: ScenarioName[];
  output?: string;
  check: boolean;
  username: string;
  amount: string;
  asset: string;
  memo?: string;
  txHash?: string;
  address?: string;
}

const baselinePath = resolve(__dirname, "load-baseline.json");

function envNumber(name: string, fallback: number): number {
  const value = process.env[name];
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) throw new Error(`${name} must be a non-negative number`);
  return parsed;
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required for this scenario`);
  return value;
}

function parseScenarios(): ScenarioName[] {
  const requested = process.env.SCENARIOS?.split(",").map((value) => value.trim()).filter(Boolean);
  const scenarios = requested?.length ? requested : ["link-creation", "payment-page-read", "receipt-read"];
  const valid = new Set<ScenarioName>(["link-creation", "payment-page-read", "receipt-read"]);
  for (const scenario of scenarios) {
    if (!valid.has(scenario as ScenarioName)) throw new Error(`Unknown scenario: ${scenario}`);
  }
  return scenarios as ScenarioName[];
}

function optionsFromEnv(): Options {
  return {
    baseUrl: (process.env.BASE_URL ?? "http://localhost:4000").replace(/\/$/, ""),
    concurrency: Math.max(1, Math.floor(envNumber("CONCURRENCY", 4))),
    durationSeconds: envNumber("DURATION_SECONDS", 30),
    timeoutMs: Math.max(1, Math.floor(envNumber("REQUEST_TIMEOUT_MS", 10000))),
    warmupSeconds: envNumber("WARMUP_SECONDS", 2),
    scenarios: parseScenarios(),
    output: process.env.RESULTS_FILE,
    check: process.env.CHECK_THRESHOLDS !== "false",
    username: process.env.PAYMENT_USERNAME ?? "load-test-user",
    amount: process.env.PAYMENT_AMOUNT ?? "1",
    asset: process.env.PAYMENT_ASSET ?? "XLM",
    memo: process.env.PAYMENT_MEMO,
    txHash: process.env.RECEIPT_TX_HASH,
    address: process.env.RECEIPT_ADDRESS,
  };
}

function percentile(values: number[], requested: number): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const index = Math.min(sorted.length - 1, Math.ceil(requested * sorted.length) - 1);
  return Number(sorted[index].toFixed(2));
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

async function request(options: Options, scenario: ScenarioName): Promise<Sample> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
  const started = performance.now();
  try {
    let path: string;
    let init: RequestInit = { signal: controller.signal };
    if (scenario === "link-creation") {
      path = "/links/metadata";
      init = { ...init, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ amount: Number(options.amount), asset: options.asset, memo: options.memo }) };
    } else if (scenario === "payment-page-read") {
      path = `/payment-links/status?username=${encodeURIComponent(options.username)}&amount=${encodeURIComponent(options.amount)}&asset=${encodeURIComponent(options.asset)}`;
    } else if (options.txHash) {
      path = `/v1/receipts/tx/${encodeURIComponent(options.txHash)}`;
    } else {
      path = `/v1/receipts/address/${encodeURIComponent(requiredEnv("RECEIPT_ADDRESS"))}`;
    }
    const response = await fetch(`${options.baseUrl}${path}`, init);
    return { durationMs: performance.now() - started, status: response.status, ...(response.ok ? {} : { error: `HTTP ${response.status}` }) };
  } catch (error) {
    return { durationMs: performance.now() - started, status: null, error: error instanceof Error ? error.message : String(error) };
  } finally {
    clearTimeout(timeout);
  }
}

async function runScenario(options: Options, config: ScenarioConfig, name: ScenarioName): Promise<ScenarioResult> {
  const samples: Sample[] = [];
  const endAt = performance.now() + options.durationSeconds * 1000;
  async function worker(): Promise<void> {
    while (performance.now() < endAt) samples.push(await request(options, name));
  }
  await Promise.all(Array.from({ length: options.concurrency }, () => worker()));
  const durations = samples.map((sample) => sample.durationMs);
  const statuses: Record<string, number> = {};
  for (const sample of samples) {
    const key = sample.status === null ? "network-error" : String(sample.status);
    statuses[key] = (statuses[key] ?? 0) + 1;
  }
  const errors = samples.filter((sample) => sample.error).length;
  const elapsedSeconds = Math.max(options.durationSeconds, 0.001);
  return { ...config, name, requests: samples.length, successes: samples.length - errors, errors, errorRate: samples.length ? Number((errors / samples.length).toFixed(4)) : 1, throughput: Number((samples.length / elapsedSeconds).toFixed(2)), p50Ms: percentile(durations, 0.5), p95Ms: percentile(durations, 0.95), p99Ms: percentile(durations, 0.99), statuses };
}

function violations(result: ScenarioResult): string[] {
  const failures: string[] = [];
  if (result.throughput < result.minThroughput) failures.push(`throughput ${result.throughput} < ${result.minThroughput} req/s`);
  if (result.p95Ms > result.maxP95Ms) failures.push(`p95 ${result.p95Ms}ms > ${result.maxP95Ms}ms`);
  if (result.p99Ms > result.maxP99Ms) failures.push(`p99 ${result.p99Ms}ms > ${result.maxP99Ms}ms`);
  if (result.errorRate > result.maxErrorRate) failures.push(`error rate ${result.errorRate} > ${result.maxErrorRate}`);
  return failures;
}

async function main(): Promise<void> {
  const options = optionsFromEnv();
  const baselines = JSON.parse(await readFile(baselinePath, "utf8")) as Record<ScenarioName, ScenarioConfig>;
  if (options.warmupSeconds > 0) {
    console.log(`Warming up ${options.baseUrl} for ${options.warmupSeconds}s...`);
    await sleep(options.warmupSeconds * 1000);
  }
  const results: ScenarioResult[] = [];
  for (const scenario of options.scenarios) {
    if (scenario === "receipt-read" && !options.txHash && !options.address) throw new Error("Set RECEIPT_TX_HASH or RECEIPT_ADDRESS for receipt-read");
    console.log(`Running ${scenario} (${options.concurrency} workers, ${options.durationSeconds}s)...`);
    results.push(await runScenario(options, baselines[scenario], scenario));
  }
  const report = { generatedAt: new Date().toISOString(), options: { ...options, check: undefined }, results };
  console.table(results.map(({ name, requests, throughput, p50Ms, p95Ms, p99Ms, errorRate }) => ({ name, requests, throughput, p50Ms, p95Ms, p99Ms, errorRate })));
  if (options.output) await writeFile(resolve(process.cwd(), options.output), `${JSON.stringify(report, null, 2)}\n`);
  if (options.check) {
    const failures = results.flatMap((result) => violations(result).map((failure) => `${result.name}: ${failure}`));
    if (failures.length) throw new Error(`Load thresholds failed:\n${failures.join("\n")}`);
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});