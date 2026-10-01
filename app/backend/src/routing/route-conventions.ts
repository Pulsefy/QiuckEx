/**
 * Route prefix conventions for HTTP controllers.
 *
 * See `docs/ROUTING-CONVENTIONS.md` for the full convention and rationale.
 *
 * `main.ts` deliberately does not call `setGlobalPrefix`, so a controller's
 * `@Controller(...)` argument *is* the public route prefix. Those prefixes had
 * drifted: `v1/receipts` was versioned, `api/environment-parity` was the only
 * `api/`-prefixed route, and every other controller was unprefixed. That
 * inconsistency is a direct contributor to the mobile
 * `/api/contracts/registry` 404 — with no rule to point at, a client had no way
 * to know which prefix a route would actually have.
 *
 * The convention, in one line: **canonical prefixes are unprefixed resource
 * paths.** Transport-environment segments — `api/`, `mobile/` — are never part
 * of a route, and versioning is not per-controller: the API version is declared
 * once in Swagger (`main.ts`), not repeated on whichever controller needed it
 * first.
 *
 * This module turns that into something checkable, so a new controller is
 * validated mechanically instead of by a reviewer remembering the rule.
 * `route-conventions.unit.spec.ts` runs the check over every
 * `src/**​/*.controller.ts` as part of the unit suite, and
 * `scripts/check-route-conventions.ts` runs the same check standalone.
 *
 * Two small sets are exempt, and both are **closed** — meaning an entry may
 * only be removed, never added:
 *
 *   - `COMPATIBILITY_ALIASES` — a non-canonical prefix kept for a client that
 *     already shipped against it. The canonical prefix must be registered
 *     alongside, so the alias can be dropped without a breaking change.
 *   - `GRANDFATHERED_VERSIONED_PREFIXES` — existing `v1/` routes with live
 *     callers. Kept as-is so no client breaks, but no new `v1/` prefix may be
 *     created, and a grandfathered controller picks up its unprefixed
 *     canonical prefix the next time it is touched.
 *
 * The unit spec fails if either set drifts from the documented tables, in
 * either direction.
 */

import * as fs from "fs";
import * as path from "path";

/** Prefix segments that must never appear in a canonical route. */
export const BANNED_PREFIX_SEGMENTS: readonly string[] = ["api", "mobile", "v1"];

/**
 * Canonical prefixes: lowercase alphanumeric segments separated by `-` within
 * a segment or `/` between segments (`contracts`, `links/recurring`,
 * `admin/abuse-signals`). A bare `@Controller()` (root) is also canonical.
 */
export const CANONICAL_PREFIX_PATTERN = /^[a-z0-9]+(?:[-/][a-z0-9]+)*$/;

/**
 * Non-canonical prefixes kept as *compatibility aliases*. Each one is
 * registered alongside its canonical prefix, so removing the alias later is
 * not a breaking change. Closed set.
 */
export const COMPATIBILITY_ALIASES: readonly string[] = [
  "api/contracts",
  "mobile/contracts",
  "api/mobile/contracts",
  "api/seed-reset",
];

/**
 * Existing `v1/` routes with live callers, grandfathered so no client breaks.
 * Closed set: adding an entry creates a new versioned route, which the
 * convention forbids. Any exception has to be argued in
 * `docs/ROUTING-CONVENTIONS.md` first.
 */
export const GRANDFATHERED_VERSIONED_PREFIXES: readonly string[] = [
  "v1/receipts",
  "v1/runtime-config",
  "v1/network",
  "v1/demo",
  "v1/contracts/views",
];

/** Every prefix allowed to be non-canonical. */
export const FROZEN_LEGACY_PREFIXES: readonly string[] = [
  ...COMPATIBILITY_ALIASES,
  ...GRANDFATHERED_VERSIONED_PREFIXES,
];

export interface ControllerSource {
  /** Repo-relative path, used in violation messages. */
  file: string;
  source: string;
}

export interface ControllerPrefixes {
  file: string;
  /** One entry per prefix; a single-prefix controller has exactly one. */
  prefixes: string[];
}

export interface Violation {
  file: string;
  prefix: string;
  reason: string;
}

/**
 * Read the string literal starting at `start` (which must be a quote).
 * Returns the literal's value and the index just past its closing quote.
 */
function readStringLiteral(
  source: string,
  start: number,
): { value: string; end: number } | null {
  const quote = source[start];
  if (quote !== '"' && quote !== "'" && quote !== "`") return null;

  let value = "";
  let i = start + 1;
  while (i < source.length) {
    const char = source[i];
    if (char === "\\") {
      // Keep escapes verbatim: route prefixes never need them, so preserving
      // them means a malformed literal fails the pattern check below loudly
      // rather than being silently unescaped.
      value += source[i + 1] ?? "";
      i += 2;
      continue;
    }
    if (char === quote) return { value, end: i + 1 };
    value += char;
    i += 1;
  }
  return null;
}

/**
 * Extract the `@Controller(...)` prefix argument(s) from a controller source.
 *
 * Handles the three shapes Nest accepts: no argument (root), a single string,
 * and an array of strings. Returns `null` when the file has no
 * `@Controller(...)` at all, which is itself a violation for a
 * `*.controller.ts` file.
 */
export function extractControllerPrefixes(source: string): string[] | null {
  const marker = /@Controller\s*\(/.exec(source);
  if (!marker) return null;

  let i = marker.index + marker[0].length;
  while (i < source.length && /\s/.test(source[i])) i += 1;

  // `@Controller()` — the root prefix.
  if (source[i] === ")") return [""];

  if (source[i] === "[") {
    const prefixes: string[] = [];
    i += 1;
    while (i < source.length) {
      while (i < source.length && /[\s,]/.test(source[i])) i += 1;
      if (source[i] === "]") break;
      if (source[i] === ")") break;
      const literal = readStringLiteral(source, i);
      if (!literal) return prefixes.length > 0 ? prefixes : null;
      prefixes.push(literal.value);
      i = literal.end;
    }
    return prefixes;
  }

  const literal = readStringLiteral(source, i);
  return literal ? [literal.value] : null;
}

/**
 * Why `prefix` is not acceptable as a canonical prefix, or `null` when it is.
 * Frozen legacy prefixes are handled by `findViolations`, not here.
 */
export function canonicalPrefixProblem(prefix: string): string | null {
  if (prefix === "") return null; // root controller — `@Controller()`

  if (prefix !== prefix.trim()) {
    return "must not be padded with whitespace";
  }
  if (prefix.startsWith("/") || prefix.endsWith("/")) {
    return "must not start or end with '/'";
  }

  const segments = prefix.split("/");
  const banned = segments.find((s) => BANNED_PREFIX_SEGMENTS.includes(s));
  if (banned) {
    return `must not carry the '${banned}/' transport prefix — routes are unprefixed resource paths (see docs/ROUTING-CONVENTIONS.md)`;
  }
  if (!CANONICAL_PREFIX_PATTERN.test(prefix)) {
    return "must be a lowercase resource path, e.g. 'contracts' or 'links/recurring'";
  }
  return null;
}

/**
 * Check every prefix of every controller. Returns one entry per offending
 * prefix, so a caller can report all of them at once.
 */
export function findViolations(controllers: ControllerSource[]): Violation[] {
  const violations: Violation[] = [];

  for (const { file, source } of controllers) {
    const prefixes = extractControllerPrefixes(source);
    if (prefixes === null) {
      violations.push({
        file,
        prefix: "(missing)",
        reason:
          "no @Controller(...) found — every *.controller.ts must declare its route prefix",
      });
      continue;
    }
    if (prefixes.length === 0) {
      violations.push({
        file,
        prefix: "(empty)",
        reason: "@Controller([]) registers no route",
      });
      continue;
    }

    for (const prefix of prefixes) {
      if (FROZEN_LEGACY_PREFIXES.includes(prefix)) continue;
      const problem = canonicalPrefixProblem(prefix);
      if (problem) {
        violations.push({ file, prefix, reason: problem });
      }
    }
  }

  return violations;
}

/** Every frozen legacy prefix that actually appears in a controller. */
export function usedLegacyPrefixes(
  controllers: ControllerSource[],
): Set<string> {
  const used = new Set<string>();
  for (const { source } of controllers) {
    const prefixes = extractControllerPrefixes(source) ?? [];
    for (const prefix of prefixes) {
      if (FROZEN_LEGACY_PREFIXES.includes(prefix)) used.add(prefix);
    }
  }
  return used;
}

/**
 * Controllers that register a compatibility alias without also registering a
 * canonical prefix — i.e. the alias could not be removed without a breaking
 * change.
 */
export function aliasesWithoutCanonicalPartner(
  controllers: ControllerSource[],
): { file: string; aliases: string[] }[] {
  const offenders: { file: string; aliases: string[] }[] = [];

  for (const { file, source } of controllers) {
    const prefixes = extractControllerPrefixes(source) ?? [];
    const aliases = prefixes.filter((p) => COMPATIBILITY_ALIASES.includes(p));
    if (aliases.length === 0) continue;

    const hasCanonical = prefixes.some(
      (p) =>
        !FROZEN_LEGACY_PREFIXES.includes(p) && canonicalPrefixProblem(p) === null,
    );
    if (!hasCanonical) offenders.push({ file, aliases });
  }

  return offenders;
}

/**
 * Recursively collect every `*.controller.ts` under `srcDir`.
 *
 * Files are read as text rather than imported: controller classes pull in
 * guards, services, and database clients, and the check only needs the
 * decorator argument. Reading text also means a *new* controller file is
 * covered automatically, with no registry to update.
 */
export function loadControllerSources(srcDir: string): ControllerSource[] {
  const sources: ControllerSource[] = [];
  const repoRoot = path.join(srcDir, "..");

  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === "dist") continue;
        walk(full);
        continue;
      }
      if (!entry.name.endsWith(".controller.ts")) continue;
      sources.push({
        file: path.relative(repoRoot, full),
        source: fs.readFileSync(full, "utf8"),
      });
    }
  };

  walk(srcDir);
  return sources.sort((a, b) => a.file.localeCompare(b.file));
}
