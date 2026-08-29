#!/usr/bin/env node
/**
 * Guards app/frontend against dependency specifiers npm cannot install.
 *
 * app/frontend is the one workspace member that installs with npm (it has its
 * own package-lock.json, and app/frontend/vercel.json pins
 * `installCommand: npm install` for production deploys). Every other member
 * installs through the root pnpm workspace.
 *
 * npm does not implement pnpm's `workspace:` protocol, so a local dependency
 * written as "workspace:*" here fails at install time with a cryptic
 *
 *     npm error code EUNSUPPORTEDPROTOCOL
 *     npm error Unsupported URL Type "workspace:": workspace:*
 *
 * which lands on the contributor rather than on the line they wrote. This
 * check turns that into an actionable message, before npm ci runs.
 *
 * Run locally with:  node scripts/check-frontend-deps.mjs
 */

import { readFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const frontendDir = resolve(repoRoot, "app/frontend");
const manifestPath = resolve(frontendDir, "package.json");

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

const errors = [];

for (const field of DEP_FIELDS) {
  for (const [name, spec] of Object.entries(manifest[field] ?? {})) {
    if (typeof spec !== "string") continue;

    if (spec.startsWith("workspace:")) {
      errors.push(
        `${field}.${name} uses "${spec}", which npm cannot install.\n` +
          `    app/frontend installs with npm, not pnpm. Use a relative file: path instead:\n` +
          `      "${name}": "file:../../packages/${name.replace(/^@[^/]+\//, "")}"\n` +
          `    Then regenerate the lockfile:  cd app/frontend && npm install`,
      );
      continue;
    }

    // A file: dep pointing at a directory that does not exist installs
    // "successfully" and then fails much later at module resolution.
    if (spec.startsWith("file:")) {
      const target = resolve(frontendDir, spec.slice("file:".length));
      if (!existsSync(target)) {
        errors.push(`${field}.${name} points at "${spec}", but ${target} does not exist.`);
      }
    }
  }
}

if (errors.length > 0) {
  console.error("app/frontend/package.json has dependency specifiers npm cannot install:\n");
  for (const error of errors) {
    console.error(`  - ${error}\n`);
  }
  process.exit(1);
}

console.log("app/frontend dependency specifiers are npm-compatible. ✓");
