/**
 * Regression tests for the mobile i18n bootstrap.
 *
 * The original defect was an import in `app/_layout.tsx` that pointed at
 * `../../src/lib/i18n`. From `app/mobile/app/` that resolves to
 * `app/src/lib/i18n`, which does not exist — so the bootstrap never ran,
 * i18next was never initialised, and every `t()` call returned the raw key.
 *
 * The JSON key-parity test could not catch this because it only reads
 * `translations.json`. These tests cover the wiring (the layout import must
 * resolve to the real bootstrap) and the runtime effect (a component rendered
 * under a non-default locale shows translated text, not the key).
 */
const fs = require('fs');
const path = require('path');
const React = require('react');
const { Text } = require('react-native');
const { render } = require('@testing-library/react-native');
const { useTranslation } = require('react-i18next');

const MOBILE_ROOT = path.resolve(__dirname, '..');
const LAYOUT_PATH = path.join(MOBILE_ROOT, 'app', '_layout.tsx');
const BOOTSTRAP_PATH = path.join(MOBILE_ROOT, 'src', 'lib', 'i18n.ts');

/** The module specifier `app/_layout.tsx` uses to boot i18next. */
function layoutI18nSpecifier() {
  const source = fs.readFileSync(LAYOUT_PATH, 'utf8');
  const match = source.match(/^\s*import\s+['"]([^'"]*lib\/i18n)['"]\s*;/m);
  if (!match) {
    throw new Error('app/_layout.tsx no longer imports a lib/i18n bootstrap');
  }
  return match[1];
}

/**
 * Resolve a specifier the way the bundler does, relative to `app/`: an explicit
 * extension first, then a directory index. A bare directory is not a module.
 */
function resolveFromApp(specifier) {
  const base = path.resolve(MOBILE_ROOT, 'app', specifier);
  const candidates = [
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.js`,
    path.join(base, 'index.ts'),
    path.join(base, 'index.tsx'),
  ];
  const hit = candidates.find((candidate) => fs.existsSync(candidate));
  if (hit) {
    return hit;
  }
  return fs.existsSync(base) && fs.statSync(base).isFile() ? base : undefined;
}

describe('mobile i18n bootstrap wiring', () => {
  it('app/_layout.tsx imports a bootstrap module that exists', () => {
    // On the broken path (`../../src/lib/i18n`) this resolves to nothing and
    // the assertion fails with `undefined`.
    expect(resolveFromApp(layoutI18nSpecifier())).toBe(BOOTSTRAP_PATH);
  });
});

describe('mobile i18n runtime', () => {
  it('renders translated text for a non-default locale instead of the raw key', async () => {
    const i18n = require('../src/lib/i18n').default;
    await i18n.changeLanguage('fr');

    function DashboardLabel() {
      // Disable Suspense so we assert against the rendered tree rather than a
      // fallback; the instance is already initialised by the bootstrap import.
      const { t } = useTranslation(undefined, { useSuspense: false });
      return React.createElement(Text, { testID: 'dashboard-label' }, t('dashboard'));
    }

    // @testing-library/react-native v14 renders asynchronously.
    const { getByTestId } = await render(React.createElement(DashboardLabel));

    expect(i18n.t('dashboard')).toBe('Tableau de Bord');
    expect(getByTestId('dashboard-label').props.children).toBe('Tableau de Bord');
  });
});
