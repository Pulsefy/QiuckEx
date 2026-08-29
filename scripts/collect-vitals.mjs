#!/usr/bin/env node
/**
 * collect-vitals.mjs (FE-66)
 *
 * Collects synthetic Core Web Vitals (LCP, CLS, INP) for a set of routes by
 * running Lighthouse against a running production server, and writes a
 * measurements JSON consumed by scripts/web-vitals.mjs:
 *
 *   [ { "page": "/pay", "metric": "LCP", "value": 2100 }, ... ]
 *
 * Lighthouse is imported dynamically so this file stays lint/type-clean even
 * where the optional dependency is not installed; when it is absent the script
 * exits non-zero and the workflow falls back to an empty measurement set.
 *
 * Usage:
 *   node scripts/collect-vitals.mjs --base-url http://localhost:3000 --routes /pay,/receipt,/dashboard --out vitals.json
 */
import { writeFileSync } from "node:fs";

function arg(flag, fallback) {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : fallback;
}

const baseUrl = arg("--base-url", "http://localhost:3000");
const routes = arg("--routes", "/pay,/receipt,/dashboard").split(",");
const outPath = arg("--out", "vitals.json");

let lighthouse;
let launch;
try {
  ({ default: lighthouse } = await import("lighthouse"));
  ({ launch } = await import("chrome-launcher"));
} catch {
  console.error(
    "[collect-vitals] lighthouse/chrome-launcher not installed; skipping collection.",
  );
  process.exit(3);
}

const chrome = await launch({ chromeFlags: ["--headless=new", "--no-sandbox"] });
const measurements = [];
try {
  for (const route of routes) {
    const runnerResult = await lighthouse(
      `${baseUrl}${route}`,
      { port: chrome.port, onlyCategories: ["performance"] },
    );
    const audits = runnerResult.lhr.audits;
    const lcp = audits["largest-contentful-paint"]?.numericValue;
    const cls = audits["cumulative-layout-shift"]?.numericValue;
    // Lighthouse reports INP as "interaction-to-next-paint" (lab: TBT proxy).
    const inp =
      audits["interaction-to-next-paint"]?.numericValue ??
      audits["total-blocking-time"]?.numericValue;

    if (lcp != null) measurements.push({ page: route, metric: "LCP", value: Math.round(lcp) });
    if (cls != null) measurements.push({ page: route, metric: "CLS", value: Math.round(cls * 1000) / 1000 });
    if (inp != null) measurements.push({ page: route, metric: "INP", value: Math.round(inp) });
  }
} finally {
  await chrome.kill();
}

writeFileSync(outPath, JSON.stringify(measurements, null, 2));
console.log(`[collect-vitals] wrote ${measurements.length} measurements to ${outPath}`);
