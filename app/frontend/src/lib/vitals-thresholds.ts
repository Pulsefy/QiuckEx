/**
 * vitals-thresholds.ts (FE-66)
 *
 * Pure classification and regression logic for Core Web Vitals. The CI script
 * collects synthetic measurements (LCP, CLS, INP) against a production build
 * and feeds them here to decide pass/flag/fail and to compute deltas against
 * the base branch. Kept pure so the policy is unit-testable.
 */

export type VitalName = "LCP" | "CLS" | "INP";
export type VitalStatus = "good" | "needs-improvement" | "poor";

export type VitalThreshold = {
  /** Upper bound for "good". */
  good: number;
  /** Upper bound for "needs-improvement"; above this is "poor". */
  poor: number;
  unit: "ms" | "";
};

/** web.dev "good/needs-improvement/poor" thresholds. */
export const DEFAULT_THRESHOLDS: Record<VitalName, VitalThreshold> = {
  LCP: { good: 2500, poor: 4000, unit: "ms" },
  CLS: { good: 0.1, poor: 0.25, unit: "" },
  INP: { good: 200, poor: 500, unit: "ms" },
};

export type VitalMeasurement = {
  page: string;
  metric: VitalName;
  value: number;
};

export type VitalResult = VitalMeasurement & {
  status: VitalStatus;
  delta: number | null;
  /** True when this measurement should fail the build per policy. */
  regressed: boolean;
};

export function classify(metric: VitalName, value: number): VitalStatus {
  const t = DEFAULT_THRESHOLDS[metric];
  if (value <= t.good) return "good";
  if (value <= t.poor) return "needs-improvement";
  return "poor";
}

export type VitalsPolicy = {
  /** Fail the build when any metric lands in "poor". Default true. */
  failOnPoor?: boolean;
};

export type VitalsReport = {
  results: VitalResult[];
  failed: boolean;
};

/**
 * Evaluate measurements against thresholds and (optionally) a base run.
 */
export function evaluateVitals(
  measurements: VitalMeasurement[],
  policy: VitalsPolicy = {},
  base?: VitalMeasurement[],
): VitalsReport {
  const failOnPoor = policy.failOnPoor ?? true;
  const baseMap = new Map(
    (base ?? []).map((m) => [`${m.page}:${m.metric}`, m.value]),
  );

  const results: VitalResult[] = measurements.map((m) => {
    const status = classify(m.metric, m.value);
    const baseValue = baseMap.get(`${m.page}:${m.metric}`);
    const regressed = failOnPoor && status === "poor";
    return {
      ...m,
      status,
      delta: baseValue === undefined ? null : round(m.value - baseValue),
      regressed,
    };
  });

  return { results, failed: results.some((r) => r.regressed) };
}

function round(n: number): number {
  return Math.round(n * 1000) / 1000;
}
