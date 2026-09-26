import * as fs from "fs";
import * as path from "path";

import {
  BANNED_PREFIX_SEGMENTS,
  COMPATIBILITY_ALIASES,
  FROZEN_LEGACY_PREFIXES,
  GRANDFATHERED_VERSIONED_PREFIXES,
  aliasesWithoutCanonicalPartner,
  canonicalPrefixProblem,
  extractControllerPrefixes,
  findViolations,
  loadControllerSources,
  usedLegacyPrefixes,
} from "./route-conventions";

/**
 * Enforces the routing convention documented in `docs/ROUTING-CONVENTIONS.md`.
 *
 * This is the "checked against the documented convention" half of that policy:
 * every `src/​**​/*.controller.ts` is read from disk, so a controller added
 * later is covered without anyone registering it here.
 */

const SRC_DIR = path.join(__dirname, "..");
const DOC_PATH = path.join(SRC_DIR, "..", "..", "..", "docs", "ROUTING-CONVENTIONS.md");

const controllers = loadControllerSources(SRC_DIR);

describe("controller route prefixes", () => {
  it("discovers controller files to check (sanity check)", () => {
    expect(controllers.length).toBeGreaterThan(40);
  });

  it("declares a prefix on every controller", () => {
    const missing = controllers.filter(
      (c) => extractControllerPrefixes(c.source) === null,
    );
    expect(missing.map((c) => c.file)).toEqual([]);
  });

  it("uses only canonical prefixes or frozen legacy prefixes", () => {
    const violations = findViolations(controllers);

    // Report every offender at once instead of failing on the first.
    if (violations.length > 0) {
      const report = violations
        .map((v) => `  ${v.file}: "${v.prefix}" ${v.reason}`)
        .join("\n");
      throw new Error(
        `Controller prefixes break docs/ROUTING-CONVENTIONS.md:\n${report}\n\n` +
          "Canonical prefixes are unprefixed resource paths. If a prefix must be " +
          "kept for an already shipped client, it belongs in COMPATIBILITY_ALIASES " +
          "with the canonical prefix registered alongside, and in the table in " +
          "docs/ROUTING-CONVENTIONS.md. No new api/, mobile/, or v1/ prefix may be " +
          "introduced.",
      );
    }

    expect(violations).toEqual([]);
  });

  it("keeps no banned transport prefix outside the frozen sets", () => {
    const offenders = controllers.flatMap(({ file, source }) =>
      (extractControllerPrefixes(source) ?? [])
        .filter((prefix) => {
          const first = prefix.split("/")[0];
          return (
            BANNED_PREFIX_SEGMENTS.includes(first) &&
            !FROZEN_LEGACY_PREFIXES.includes(prefix)
          );
        })
        .map((prefix) => `${file}: ${prefix}`),
    );
    expect(offenders).toEqual([]);
  });

  it("has no stale or undocumented frozen prefix", () => {
    // The frozen sets and the doc tables must move together in both
    // directions: a prefix in use has to be documented, and a documented
    // prefix that is no longer used is dead weight — drop the entry and the
    // controller's legacy prefix with it.
    const doc = fs.readFileSync(DOC_PATH, "utf8");
    const used = usedLegacyPrefixes(controllers);

    expect([...used].filter((prefix) => !doc.includes(prefix))).toEqual([]);
    expect(
      FROZEN_LEGACY_PREFIXES.filter((prefix) => !used.has(prefix)),
    ).toEqual([]);
    for (const prefix of FROZEN_LEGACY_PREFIXES) {
      expect(doc).toContain(prefix);
    }
  });

  it("registers the canonical prefix alongside every compatibility alias", () => {
    // An alias without a canonical partner could not be removed later without
    // a breaking change, which defeats the point of keeping it.
    expect(aliasesWithoutCanonicalPartner(controllers)).toEqual([]);
  });

  it("keeps the compatibility-alias and grandfathered sets disjoint", () => {
    // A prefix is either a removable alias (canonical partner required) or a
    // grandfathered versioned route. Overlap would make the rules ambiguous.
    const overlap = COMPATIBILITY_ALIASES.filter((prefix) =>
      GRANDFATHERED_VERSIONED_PREFIXES.includes(prefix),
    );
    expect(overlap).toEqual([]);
  });

  it("grandfathers only v1/ routes that a client actually calls", () => {
    // `v1/` is the deprecated shape; the allowlist exists for shipped callers,
    // so every entry must be a `v1/` prefix. Anything else is a mistake here.
    for (const prefix of GRANDFATHERED_VERSIONED_PREFIXES) {
      expect(prefix.startsWith("v1/")).toBe(true);
    }
  });
});

describe("route convention parser", () => {
  it("reads a single string prefix", () => {
    expect(extractControllerPrefixes('@Controller("contracts")')).toEqual([
      "contracts",
    ]);
  });

  it("reads an array of prefixes", () => {
    expect(
      extractControllerPrefixes('@Controller(["contracts", "api/contracts"])'),
    ).toEqual(["contracts", "api/contracts"]);
  });

  it("reads the root prefix from a bare decorator", () => {
    expect(extractControllerPrefixes("@Controller()")).toEqual([""]);
  });

  it("tolerates whitespace inside the decorator", () => {
    expect(
      extractControllerPrefixes("@Controller(  'links/recurring'  )"),
    ).toEqual(["links/recurring"]);
  });

  it("returns null when there is no decorator", () => {
    expect(extractControllerPrefixes("export class X {}")).toBeNull();
  });

  it("rejects banned transport prefixes", () => {
    for (const prefix of ["api/contracts", "mobile/contracts", "v1/receipts"]) {
      expect(canonicalPrefixProblem(prefix)).toMatch(/transport prefix/);
    }
  });

  it("accepts canonical resource paths", () => {
    for (const prefix of [
      "contracts",
      "admin/abuse-signals",
      "links/recurring",
      "developer/testnet",
      "",
    ]) {
      expect(canonicalPrefixProblem(prefix)).toBeNull();
    }
  });

  it("rejects malformed prefixes", () => {
    expect(canonicalPrefixProblem("/contracts")).toMatch(/must not start/);
    expect(canonicalPrefixProblem("contracts/")).toMatch(/must not start/);
    expect(canonicalPrefixProblem("Contracts")).toMatch(/lowercase/);
    expect(canonicalPrefixProblem(" contracts")).toMatch(/whitespace/);
  });
});
