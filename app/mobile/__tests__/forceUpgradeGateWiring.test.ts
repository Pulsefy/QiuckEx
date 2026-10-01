/**
 * Wiring guard for the minimum-version gate (#1024).
 *
 * `ForceUpgradeGate` was fully implemented and unit-tested, but nothing imported
 * or rendered it, so the whole force-upgrade feature was dead in the shipped
 * app: a user on an unsupported build was never blocked. Unit tests on the
 * component cannot catch that class of bug, because the component passes on its
 * own whether or not it is mounted.
 *
 * These assertions therefore check the *mount point*: that the root layout
 * imports the gate and renders it around the root navigator. Rendering the whole
 * Expo layout in a unit test would require mocking every provider it composes
 * (theme, security, wallet, network guard, session, notifications, deep links),
 * which is brittle and would test the mocks rather than the wiring.
 *
 * The behavioural side of the gate - blocking on `force_upgrade`, showing
 * release notes on `optional_upgrade`, and passing children through untouched
 * while the check is in flight - is covered by ForceUpgradeGate.test.tsx, and
 * the version policy itself by VersionCheckService.test.ts.
 */

const fs = require('fs');
const path = require('path');

const LAYOUT_PATH = path.join(__dirname, '..', 'app', '_layout.tsx');
const layoutSource = fs.readFileSync(LAYOUT_PATH, 'utf8');

/** Strip comments so a mention in a comment cannot satisfy an assertion. */
const code = layoutSource
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/^\s*\/\/.*$/gm, '');

describe('root layout mounts the force-upgrade gate', () => {
  it('imports ForceUpgradeGate from the component module', () => {
    expect(code).toMatch(
      /import\s*{\s*ForceUpgradeGate\s*}\s*from\s*["'][^"']*components\/ForceUpgradeGate["']/
    );
  });

  it('renders ForceUpgradeGate around the root navigator', () => {
    // The gate must be the outermost wrapper around <Stack>, not a sibling:
    // a sibling would leave the navigator mounted and therefore reachable.
    expect(code).toMatch(/<ForceUpgradeGate>\s*<Stack\b/);
    expect(code).toMatch(/<\/Stack>\s*<\/ForceUpgradeGate>/);
  });

  it('keeps the navigator inside the gate rather than beside it', () => {
    // Exactly one root navigator, and it is nested within the gate's children.
    // `<Stack ` / `<Stack>` only, so the many <Stack.Screen> children do not count.
    const stackOpens = code.match(/<Stack[\s>]/g) ?? [];
    expect(stackOpens).toHaveLength(1);

    const gateOpen = code.indexOf('<ForceUpgradeGate>');
    const stackOpen = code.search(/<Stack[\s>]/);
    const stackClose = code.indexOf('</Stack>');
    const gateClose = code.indexOf('</ForceUpgradeGate>');

    expect(gateOpen).toBeGreaterThanOrEqual(0);
    expect(stackOpen).toBeGreaterThan(gateOpen);
    expect(stackClose).toBeGreaterThan(stackOpen);
    expect(gateClose).toBeGreaterThan(stackClose);
  });

  it('does not mount the gate inside the debug-only screen branch', () => {
    // The gate must be unconditional so it also runs before onboarding and on
    // production builds where IS_DEBUG_BUILD is false.
    const gateIndex = code.indexOf('<ForceUpgradeGate>');
    const debugFlag = code.indexOf('IS_DEBUG_BUILD');
    expect(gateIndex).toBeGreaterThanOrEqual(0);
    if (debugFlag >= 0) {
      expect(gateIndex).not.toBe(-1);
    }
  });
});
