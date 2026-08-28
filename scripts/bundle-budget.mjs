#!/usr/bin/env node
/**
 * bundle-budget.mjs (FE-65)
 *
 * Measures per-route first-load JS from a production Next.js build and enforces
 * the budgets in app/frontend/bundle-budgets.json. Fails CI when a route
 * exceeds its budget (plus tolerance) and prints a delta against a base report
 * when one is supplied.
 *
 * Usage:
 *   node scripts/bundle-budget.mjs \
 *     --dist app/frontend/.next \
 *     --budgets app/frontend/bundle-budgets.json \
 *     [--base bundle-sizes.base.json] \
 *     [--out bundle-sizes.json]
 *
 * The route→sizes computation mirrors app/frontend/src/lib/bundle-budget.ts,
 * which is unit-tested.
 */
import { readFileSync, existsSync, writeFileSync, statSync } from "node:fs";
import path from "node:path";

function arg(flag, fallback) {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : fallback;
}

const distDir = arg("--dist", "app/frontend/.next");
const budgetsPath = arg("--budgets", "app/frontend/bundle-budgets.json");
const basePath = arg("--base");
const outPath = arg("--out");

function fileSize(p) {
  try {
    return statSync(p).size;
  } catch {
    return 0;
  }
}

/** Sum the byte size of the JS files each App Router route pulls in. */
function measureRoutes(dist) {
  const manifestPath = path.join(dist, "app-build-manifest.json");
  if (!existsSync(manifestPath)) {
    console.error(
      `[bundle-budget] ${manifestPath} not found — run \`next build\` first.`,
    );
    process.exit(2);
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const pages = manifest.pages ?? {};
  return Object.entries(pages).map(([page, files]) => {
    const bytes = files
      .filter((f) => f.endsWith(".js"))
      .reduce((sum, f) => sum + fileSize(path.join(dist, f)), 0);
    // Normalise the App Router page key (e.g. "/pay/page") to a route.
    const route = page.replace(/\/page$/, "") || "/";
    return { route, bytes };
  });
}

function formatBytes(bytes) {
  if (Math.abs(bytes) < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  return kb < 1024 ? `${kb.toFixed(1)} KB` : `${(kb / 1024).toFixed(2)} MB`;
}

function formatDelta(delta) {
  if (delta === null || delta === undefined) return "—";
  if (delta === 0) return "±0 B";
  return `${delta > 0 ? "+" : "−"}${formatBytes(Math.abs(delta))}`;
}

const { budgets, tolerance = 0 } = JSON.parse(readFileSync(budgetsPath, "utf8"));
const budgetMap = new Map(budgets.map((b) => [b.route, b.maxBytes]));
const sizes = measureRoutes(distDir);
const baseMap = basePath && existsSync(basePath)
  ? new Map(JSON.parse(readFileSync(basePath, "utf8")).map((s) => [s.route, s.bytes]))
  : null;

if (outPath) writeFileSync(outPath, JSON.stringify(sizes, null, 2));

let failed = false;
console.log("\nRoute bundle sizes (first-load JS):\n");
console.log(
  ["Route", "Size", "Budget", "Δ base", "Status"]
    .map((h) => h.padEnd(16))
    .join(""),
);
for (const { route, bytes } of sizes.sort((a, b) => b.bytes - a.bytes)) {
  const maxBytes = budgetMap.get(route) ?? null;
  const limit = maxBytes === null ? null : Math.floor(maxBytes * (1 + tolerance));
  const over = limit !== null && bytes > limit;
  const delta = baseMap?.has(route) ? bytes - baseMap.get(route) : null;
  if (over) failed = true;
  console.log(
    [
      route,
      formatBytes(bytes),
      maxBytes === null ? "—" : formatBytes(maxBytes),
      formatDelta(delta),
      over ? "OVER" : maxBytes === null ? "(no budget)" : "ok",
    ]
      .map((c) => String(c).padEnd(16))
      .join(""),
  );
}

if (failed) {
  console.error(
    "\n[bundle-budget] One or more routes exceeded their budget. " +
      "See docs/FRONTEND-PERFORMANCE.md to adjust a budget deliberately.",
  );
  process.exit(1);
}
console.log("\n[bundle-budget] All routes within budget.\n");
