#!/usr/bin/env node
// Mobile i18n key-parity check.
//
// Reads the mobile translation dictionary (src/lib/i18n/translations.json) and
// fails when any non-base locale is missing a key that exists in the base
// locale (`en`). Missing keys are reported per locale by name so CI output makes
// it obvious which strings need translating.
//
// Usage: node scripts/check-i18n-parity.mjs [path-to-translations.json]
//
// Exit codes:
//   0  parity OK (every locale has all base keys)
//   1  at least one locale is missing a base key
//   2  usage / file error

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const BASE_LOCALE = process.env.I18N_BASE_LOCALE || 'en';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultPath = resolve(scriptDir, '../src/lib/i18n/translations.json');
const translationsPath = resolve(process.argv[2] || defaultPath);

let translations;
try {
  translations = JSON.parse(readFileSync(translationsPath, 'utf8'));
} catch (err) {
  console.error(`::error::Could not read translation dictionary at ${translationsPath}: ${err.message}`);
  process.exit(2);
}

const locales = Object.keys(translations);
if (!locales.includes(BASE_LOCALE)) {
  console.error(`::error::Base locale "${BASE_LOCALE}" is not present in ${translationsPath}. Found: ${locales.join(', ')}`);
  process.exit(2);
}

const baseKeys = Object.keys(translations[BASE_LOCALE]).sort();
const checked = locales.filter((l) => l !== BASE_LOCALE);

let failed = false;

console.log(`i18n key parity — base locale: ${BASE_LOCALE}, locales checked: ${checked.join(', ') || '(none)'}\n`);

for (const locale of checked) {
  const localeKeys = new Set(Object.keys(translations[locale]));
  const missing = baseKeys.filter((k) => !localeKeys.has(k));
  const extra = Object.keys(translations[locale]).filter((k) => !baseKeys.includes(k));

  if (missing.length === 0 && extra.length === 0) {
    console.log(`  ✅ ${locale}: ${localeKeys.size} keys, parity with ${BASE_LOCALE}`);
    continue;
  }

  if (missing.length > 0) {
    failed = true;
    console.error(`  ❌ ${locale}: missing ${missing.length} key(s) present in ${BASE_LOCALE}:`);
    for (const k of missing) console.error(`       - ${k}`);
  }

  if (extra.length > 0) {
    console.warn(`  ⚠️  ${locale}: has ${extra.length} key(s) not in ${BASE_LOCALE} (dead strings):`);
    for (const k of extra) console.warn(`       - ${k}`);
  }
}

if (failed) {
  console.error(
    `\n::error::Translation parity failed. Add the missing keys to each locale in ${translationsPath} ` +
      `(or remove them from the base locale).`,
  );
  process.exit(1);
}

console.log(`\n✅ All ${checked.length} mobile locale(s) are at parity with "${BASE_LOCALE}" (${baseKeys.length} keys).`);
