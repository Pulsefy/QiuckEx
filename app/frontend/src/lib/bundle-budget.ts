/**
 * bundle-budget.ts (FE-65)
 *
 * Pure logic for enforcing per-route bundle-size budgets in CI. The CI script
 * extracts per-route sizes from the production build and feeds them here; this
 * module decides pass/fail (with tolerance) and computes the delta against the
 * base branch so the logic is unit-testable without a real build.
 */

export type RouteSize = { route: string; bytes: number };
export type RouteBudget = { route: string; maxBytes: number };

export type BudgetResult = {
  route: string;
  bytes: number;
  maxBytes: number | null;
  /** Allowed ceiling after applying tolerance. */
  limit: number | null;
  over: boolean;
  /** Byte delta vs the base branch, when a base is provided. */
  deltaBytes: number | null;
};

export type BudgetReport = {
  results: BudgetResult[];
  failed: boolean;
};

function toMap(sizes: RouteSize[]): Map<string, number> {
  return new Map(sizes.map((s) => [s.route, s.bytes]));
}

/**
 * Evaluate current per-route sizes against budgets.
 *
 * @param sizes     current build sizes per route
 * @param budgets   configured budgets per route
 * @param tolerance fractional slack over the budget (e.g. 0.05 = 5%)
 * @param baseSizes optional base-branch sizes for delta reporting
 */
export function evaluateBudgets(
  sizes: RouteSize[],
  budgets: RouteBudget[],
  tolerance = 0,
  baseSizes?: RouteSize[],
): BudgetReport {
  const budgetMap = new Map(budgets.map((b) => [b.route, b.maxBytes]));
  const baseMap = baseSizes ? toMap(baseSizes) : null;

  const results: BudgetResult[] = sizes.map(({ route, bytes }) => {
    const maxBytes = budgetMap.has(route) ? budgetMap.get(route)! : null;
    const limit = maxBytes === null ? null : Math.floor(maxBytes * (1 + tolerance));
    const over = limit !== null && bytes > limit;
    const base = baseMap?.get(route);
    return {
      route,
      bytes,
      maxBytes,
      limit,
      over,
      deltaBytes: base === undefined ? null : bytes - base,
    };
  });

  return { results, failed: results.some((r) => r.over) };
}

/** Format a byte count as a compact human string (e.g. 131072 → "128.0 KB"). */
export function formatBytes(bytes: number): string {
  if (Math.abs(bytes) < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (Math.abs(kb) < 1024) return `${kb.toFixed(1)} KB`;
  return `${(kb / 1024).toFixed(2)} MB`;
}

/** Signed delta string for CI comment output (e.g. "+12.0 KB", "−3.0 KB"). */
export function formatDelta(deltaBytes: number | null): string {
  if (deltaBytes === null) return "—";
  if (deltaBytes === 0) return "±0 B";
  const sign = deltaBytes > 0 ? "+" : "−";
  return `${sign}${formatBytes(Math.abs(deltaBytes))}`;
}
