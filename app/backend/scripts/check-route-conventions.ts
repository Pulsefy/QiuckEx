#!/usr/bin/env ts-node
/**
 * Route convention check — the standalone (non-jest) entry point for
 * `docs/ROUTING-CONVENTIONS.md`.
 *
 * The same check runs inside the unit suite as
 * `src/routing/route-conventions.unit.spec.ts`; this script exists so CI, a
 * pre-commit hook, or a reviewer can run it without booting jest:
 *
 *   pnpm --filter @quickex/backend check:routes
 *   npx ts-node scripts/check-route-conventions.ts
 *
 * Exits 1 with a report when a controller prefix breaks the convention.
 */

import * as path from "path";

import {
  findViolations,
  loadControllerSources,
} from "../src/routing/route-conventions";

const srcDir = path.join(__dirname, "..", "src");
const controllers = loadControllerSources(srcDir);

if (controllers.length === 0) {
  // A silent pass on zero files would hide a broken path, not a clean repo.
  console.error(
    `[check-route-conventions] No controllers found under ${srcDir} — refusing to report success.`,
  );
  process.exit(1);
}

const violations = findViolations(controllers);

if (violations.length === 0) {
  console.log(
    `[check-route-conventions] OK — ${controllers.length} controllers follow docs/ROUTING-CONVENTIONS.md.`,
  );
  process.exit(0);
}

console.error(
  `[check-route-conventions] ${violations.length} prefix violation(s) across ${controllers.length} controllers:\n`,
);
for (const { file, prefix, reason } of violations) {
  console.error(`  ${file}\n    "${prefix}" ${reason}\n`);
}
console.error(
  "Canonical prefixes are unprefixed resource paths. A prefix kept for an\n" +
    "already shipped client belongs in COMPATIBILITY_ALIASES\n" +
    "(src/routing/route-conventions.ts) and in the table in\n" +
    "docs/ROUTING-CONVENTIONS.md, with the canonical prefix registered too.\n",
);
process.exit(1);
