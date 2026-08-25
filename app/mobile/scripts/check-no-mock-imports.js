#!/usr/bin/env node
/**
 * check-no-mock-imports.js
 *
 * CI guard: fails if any production source file imports a mock data fixture.
 *
 * "Production source file" = anything under app/mobile that is NOT inside:
 *   - __tests__/
 *   - __mocks__/
 *   - *.test.ts(x)
 *   - *.spec.ts(x)
 *
 * "Mock data import" = any import/require whose path contains one of the
 * banned segments defined in MOCK_PATH_PATTERNS.
 *
 * Usage (from repo root or app/mobile):
 *   node scripts/check-no-mock-imports.js
 *
 * Exit code 0 = clean. Exit code 1 = violations found.
 */

'use strict';

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const ROOT = path.resolve(__dirname, '..');

/**
 * Directories / file patterns that are allowed to import mock data.
 * Paths are matched against the absolute file path.
 */
const ALLOWED_PATTERNS = [
  /__tests__[/\\]/,
  /__mocks__[/\\]/,
  /\.test\.[jt]sx?$/,
  /\.spec\.[jt]sx?$/,
];

/**
 * Import path segments that indicate a mock data file.
 * Matched against the raw import string (not the resolved path).
 */
const MOCK_PATH_PATTERNS = [
  /[/\\]src[/\\]data[/\\]mock/,   // e.g. ../src/data/mockReceipt
  /[/\\]data[/\\]mock/,            // shorter relative forms
  /[/\\]fixtures[/\\]mock/,        // __tests__/fixtures/mock* — only bad when imported from prod
  /mockReceipt/,                    // direct filename match regardless of path
  /mockData/,
  /mock-data/,
];

/** File extensions to scan. */
const SCAN_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isAllowed(filePath) {
  return ALLOWED_PATTERNS.some((re) => re.test(filePath));
}

function hasMockImport(source) {
  // Match both static imports and require() calls.
  const importRe = /(?:import\s[^'"]*from\s|require\s*\(\s*)['"]([^'"]+)['"]/g;
  let match;
  while ((match = importRe.exec(source)) !== null) {
    const importPath = match[1];
    if (MOCK_PATH_PATTERNS.some((re) => re.test(importPath))) {
      return importPath;
    }
  }
  return null;
}

function walk(dir, results = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      // Skip node_modules and hidden dirs (e.g. .expo, .turbo)
      if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
      walk(full, results);
    } else if (entry.isFile() && SCAN_EXTENSIONS.has(path.extname(entry.name))) {
      results.push(full);
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const allFiles = walk(ROOT);
const violations = [];

for (const file of allFiles) {
  if (isAllowed(file)) continue;

  let source;
  try {
    source = fs.readFileSync(file, 'utf8');
  } catch {
    continue;
  }

  const offendingImport = hasMockImport(source);
  if (offendingImport) {
    violations.push({ file: path.relative(ROOT, file), import: offendingImport });
  }
}

if (violations.length === 0) {
  console.log('✅  check-no-mock-imports: no violations found.');
  process.exit(0);
} else {
  console.error(
    `\n❌  check-no-mock-imports: ${violations.length} production file(s) import mock data.\n`,
  );
  for (const v of violations) {
    console.error(`  ${v.file}\n    imports: "${v.import}"\n`);
  }
  console.error(
    'Mock fixtures must live under __tests__/fixtures/ and must only be\n' +
    'imported from test files (*.test.ts, *.spec.ts, __tests__/**).\n',
  );
  process.exit(1);
}
