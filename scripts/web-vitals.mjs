#!/usr/bin/env node
/**
 * web-vitals.mjs (FE-66)
 *
 * Applies Core Web Vitals thresholds to synthetic measurements collected
 * against a PRODUCTION build (see .github/workflows/frontend-web-vitals.yml,
 * which runs Lighthouse over `next start` for the key public routes and writes
 * a measurements JSON). This script evaluates them, prints a PR-friendly
 * report with a delta against the base branch, and fails per the documented
 * policy. The classification logic mirrors
 * app/frontend/src/lib/vitals-thresholds.ts, which is unit-tested.
 *
 * Usage:
 *   node scripts/web-vitals.mjs --input vitals.json [--base vitals.base.json] [--flag-only]
 */
import { readFileSync, existsSync } from "node:fs";

function arg(flag, fallback) {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : fallback;
}
const hasFlag = (f) => process.argv.includes(f);

const THRESHOLDS = {
  LCP: { good: 2500, poor: 4000, unit: "ms" },
  CLS: { good: 0.1, poor: 0.25, unit: "" },
  INP: { good: 200, poor: 500, unit: "ms" },
};

function classify(metric, value) {
  const t = THRESHOLDS[metric];
  if (value <= t.good) return "good";
  if (value <= t.poor) return "needs-improvement";
  return "poor";
}

const inputPath = arg("--input", "vitals.json");
const basePath = arg("--base");
const failOnPoor = !hasFlag("--flag-only");

if (!existsSync(inputPath)) {
  console.error(`[web-vitals] measurements file ${inputPath} not found.`);
  process.exit(2);
}
const measurements = JSON.parse(readFileSync(inputPath, "utf8"));
const baseMap =
  basePath && existsSync(basePath)
    ? new Map(
        JSON.parse(readFileSync(basePath, "utf8")).map((m) => [
          `${m.page}:${m.metric}`,
          m.value,
        ]),
      )
    : null;

let failed = false;
console.log("\nCore Web Vitals (synthetic, production build):\n");
console.log(
  ["Page", "Metric", "Value", "Δ base", "Status"]
    .map((h) => h.padEnd(14))
    .join(""),
);
for (const m of measurements) {
  const status = classify(m.metric, m.value);
  const base = baseMap?.get(`${m.page}:${m.metric}`);
  const delta = base === undefined ? null : Math.round((m.value - base) * 1000) / 1000;
  if (failOnPoor && status === "poor") failed = true;
  console.log(
    [
      m.page,
      m.metric,
      `${m.value}${THRESHOLDS[m.metric].unit}`,
      delta === null ? "—" : (delta > 0 ? `+${delta}` : `${delta}`),
      status,
    ]
      .map((c) => String(c).padEnd(14))
      .join(""),
  );
}

if (failed) {
  console.error(
    "\n[web-vitals] A key route regressed into the 'poor' band. " +
      "See docs/FRONTEND-PERFORMANCE.md for the policy.",
  );
  process.exit(1);
}
console.log("\n[web-vitals] All measured routes within policy.\n");
