/**
 * i18n key-parity test for the frontend translation dictionaries.
 *
 * Ensures every non-base locale (es, fr) has exactly the same keys as the
 * base locale (en).  Fails on missing keys (locale is missing a key present
 * in en) or dead keys (locale has a key absent from en).
 */

import translations from '../src/lib/i18n/translations.json';

const BASE_LOCALE = 'en';

describe('frontend i18n key parity', () => {
  const baseKeys = Object.keys(
    translations[BASE_LOCALE] as Record<string, string>,
  );
  const locales = Object.keys(translations).filter((l) => l !== BASE_LOCALE);

  it('defines a non-empty base locale', () => {
    expect(baseKeys.length).toBeGreaterThan(0);
  });

  it.each(locales)(
    'locale "%s" contains every base key',
    (locale) => {
      const keys = Object.keys(
        translations[locale as 'es' | 'fr'] as Record<string, string>,
      );
      const missing = baseKeys.filter((k) => !keys.includes(k));
      expect(missing).toEqual([]);
    },
  );

  it.each(locales)(
    'locale "%s" has no dead keys missing from the base',
    (locale) => {
      const keys = Object.keys(
        translations[locale as 'es' | 'fr'] as Record<string, string>,
      );
      const extra = keys.filter((k) => !baseKeys.includes(k));
      expect(extra).toEqual([]);
    },
  );
});
