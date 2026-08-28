import { readFile } from "node:fs/promises";

export type ScenarioName = "link-create" | "payment-page-read" | "receipt-read";

export type ScenarioConfig = {
  name: ScenarioName;
  method: "GET" | "POST";
  path: string;
  body?: Record<string, unknown>;
};

export type Thresholds = {
  maxErrorRate: number;
  maxP95Ms: number;
  maxP99Ms: number;
  minThroughput: number;
};

export type LoadConfig = {
  baseUrl: string;
  concurrency: number;
  durationSeconds?: number;
  requests?: number;
  timeoutMs: number;
  scenarios: ScenarioConfig[];
  thresholds?: Partial<Record<ScenarioName, Thresholds>>;
  headers?: Record<string, string>;
};

export type RequestResult = {
  scenario: ScenarioName;
  ok: boolean;
  status?: number;
  latencyMs: number;
  error?: string;
};

export type ScenarioReport = {
  scenario: ScenarioName;
  requests: number;
  successes: number;
  errors: number;
  errorRate: number;
  throughput: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
};

export type LoadReport = {
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  totalRequests: number;
  scenarios: ScenarioReport[];
  passed: boolean;
  failures: string[];
};

type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

export function percentile(values: number[], percentileValue: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.ceil((percentileValue / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(rank, sorted.length - 1))];
}

export function parsePositiveInteger(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`Expected a positive integer, received: ${value}`);
  }
  return parsed;
}

export function evaluateThresholds(
  report: ScenarioReport,
  thresholds: Thresholds,
): string[] {
  const failures: string[] = [];
  if (report.errorRate > thresholds.maxErrorRate) {
    failures.push(
      `${report.scenario} error rate ${formatPercent(report.errorRate)} exceeds ${formatPercent(thresholds.maxErrorRate)}`,
    );
  }
  if (report.p95Ms > thresholds.maxP95Ms) {
    failures.push(`${report.scenario} p95 ${report.p95Ms}ms exceeds ${thresholds.maxP95Ms}ms`);
  }
  if (report.p99Ms > thresholds.maxP99Ms) {
    failures.push(`${report.scenario} p99 ${report.p99Ms}ms exceeds ${thresholds.maxP99Ms}ms`);
  }
  if (report.throughput < thresholds.minThroughput) {
    failures.push(
      `${report.scenario} throughput ${report.throughput} req/s is below ${thresholds.minThroughput} req/s`,
    );
  }
  return failures;
}

export async function runLoad(
  config: LoadConfig,
  fetchImpl: FetchLike = fetch,
): Promise<LoadReport> {
  if (config.scenarios.length === 0) throw new Error("At least one scenario is required");
  if (!config.durationSeconds && !config.requests) {
    throw new Error("Set either durationSeconds or requests");
  }

  const started = Date.now();
  const results: RequestResult[] = [];
  let nextRequest = 0;
  const deadline = config.durationSeconds
    ? started + config.durationSeconds * 1000
    : Number.POSITIVE_INFINITY;

  const worker = async (): Promise<void> => {
    while (Date.now() < deadline) {
      const requestNumber = nextRequest++;
      if (config.requests && requestNumber >= config.requests) return;
      const scenario = config.scenarios[requestNumber % config.scenarios.length];
      results.push(await executeRequest(config, scenario, fetchImpl));
    }
  };

  await Promise.all(
    Array.from({ length: config.concurrency }, () => worker()),
  );

  const finished = Date.now();
  const durationMs = Math.max(1, finished - started);
  const reports = config.scenarios.map((scenario) => {
    const scenarioResults = results.filter((result) => result.scenario === scenario.name);
    return summarizeScenario(scenario.name, scenarioResults, durationMs);
  });
  const failures = reports.flatMap((report) => {
    const threshold = config.thresholds?.[report.scenario];
    return threshold ? evaluateThresholds(report, threshold) : [];
  });

  return {
    startedAt: new Date(started).toISOString(),
    finishedAt: new Date(finished).toISOString(),
    durationMs,
    totalRequests: results.length,
    scenarios: reports,
    passed: failures.length === 0,
    failures,
  };
}

async function executeRequest(
  config: LoadConfig,
  scenario: ScenarioConfig,
  fetchImpl: FetchLike,
): Promise<RequestResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs);
  const started = performance.now();
  try {
    const response = await fetchImpl(new URL(scenario.path, config.baseUrl), {
      method: scenario.method,
      headers: {
        accept: "application/json",
        ...(scenario.body ? { "content-type": "application/json" } : {}),
        ...config.headers,
      },
      body: scenario.body ? JSON.stringify(scenario.body) : undefined,
      signal: controller.signal,
    });
    return {
      scenario: scenario.name,
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      latencyMs: round(performance.now() - started),
      ...((response.status < 200 || response.status >= 300)
        ? { error: `HTTP ${response.status}` }
        : {}),
    };
  } catch (error) {
    return {
      scenario: scenario.name,
      ok: false,
      latencyMs: round(performance.now() - started),
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    clearTimeout(timeout);
  }
}

function summarizeScenario(
  scenario: ScenarioName,
  results: RequestResult[],
  durationMs: number,
): ScenarioReport {
  const latencies = results.map((result) => result.latencyMs);
  const errors = results.filter((result) => !result.ok).length;
  return {
    scenario,
    requests: results.length,
    successes: results.length - errors,
    errors,
    errorRate: results.length === 0 ? 1 : errors / results.length,
    throughput: round((results.length * 1000) / durationMs),
    p50Ms: percentile(latencies, 50),
    p95Ms: percentile(latencies, 95),
    p99Ms: percentile(latencies, 99),
  };
}

export function formatPercent(value: number): string {
  return `${(value * 100).toFixed(2)}%`;
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}

export async function readJsonFile<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}
