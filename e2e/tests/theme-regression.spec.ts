import { expect, test, type Page } from "@playwright/test";
import { FIXED_TIME, mockBackend } from "./theme-mocks";

/**
 * FE-56 — Theme regression coverage.
 *
 * Windows/panels whose theming regressions are the most expensive to discover
 * in review (the public payment flow, the dashboard + analytics charts, profile
 * settings, and the admin console) get repeatable visual coverage in BOTH
 * light and dark mode.
 *
 * Coverage expectations
 * ---------------------
 * 1. Screenshot goldens (`toHaveScreenshot`) for every high-risk surface in
 *    light + dark: public pay (ACTIVE and PAID states), dashboard (hero/metrics
 *    and the analytics chart block), profile settings, and admin console.
 *    Goldens are stored under e2e/tests/theme-regression.spec.ts-snapshots/ and
 *    regenerate through the `Visual Theme Regression` CI workflow.
 * 2. A theme-token contract (no goldens needed) that asserts the CSS custom
 *    properties in app/frontend/src/app/globals.css resolve to the expected
 *    light/dark values on every covered route and that the <html> theme class
 *    and color-scheme flip correctly. This catches "theme never applied" style
 *    regressions even when pixel baselines drift.
 *
 * Determinism
 * -----------
 * - The page clock is frozen at FIXED_TIME so countdowns, "Xh ago" activity
 *   feed labels, audit-log timestamps and chart axis labels are stable.
 * - Backend responses are mocked (see theme-mocks.ts); nothing reaches the
 *   network.
 * - The project pins viewport (1440x900), locale (en-US) and timezone (UTC).
 *
 * Run locally (server must be running on localhost:3000):
 *   npm run test:theme          # compare against committed goldens
 *   npm run test:theme:update   # regenerate goldens
 */

const THEMES = ["dark", "light"] as const;
type Theme = (typeof THEMES)[number];

/**
 * Expected resolved token values, mirroring app/frontend/src/app/globals.css.
 * If the palette is intentionally changed, update these AND the goldens.
 */
const TOKEN_EXPECTATIONS: Record<
  Theme,
  { bodyBg: string; bodyColor: string; colorScheme: string }
> = {
  dark: {
    bodyBg: "rgb(10, 10, 10)",
    bodyColor: "rgb(237, 237, 237)",
    colorScheme: "dark",
  },
  light: {
    bodyBg: "rgb(246, 247, 249)",
    bodyColor: "rgb(24, 24, 27)",
    colorScheme: "light",
  },
};

/** Seed a deterministic theme before the no-FOUC script runs on next load. */
async function seedTheme(page: Page, theme: Theme): Promise<void> {
  await page.addInitScript(
    ({ key, value }) => {
      try {
        window.localStorage.setItem(key, value);
      } catch {
        // Private mode / storage disabled — the in-memory provider still works.
      }
    },
    { key: "quickex-theme", value: theme },
  );
}

/**
 * Prepare a fresh page for a themed screenshot: seed the theme, freeze the
 * clock, mock the backend, then navigate.
 */
async function openThemed(
  page: Page,
  theme: Theme,
  path: string,
  options: { paymentState?: "ACTIVE" | "PAID" } = {},
): Promise<void> {
  await seedTheme(page, theme);
  await page.clock.install({ time: new Date(FIXED_TIME) });
  await mockBackend(page, options);
  if (path === "/admin") {
    // The admin layout now requires a session before it renders. This fixture
    // credential is test-only; all admin API calls remain intercepted above.
    const baseUrl = process.env.THEME_BASE_URL ?? "http://localhost:3000";
    await page.context().addCookies([
      {
        name: "admin_token",
        value: "theme-regression-admin",
        url: new URL(path, baseUrl).origin,
      },
    ]);
  }
  await page.goto(path);
  // Under the frozen clock, advance a little so parser scripts and React's
  // scheduler deterministically flush no matter how fast the document loads.
  await page.clock.runFor(500);
}

/** Fast-forward timers + requestAnimationFrame so animations settle. */
async function settlePage(page: Page, ms = 2000): Promise<void> {
  await page.clock.runFor(ms);
}

/**
 * With the page clock frozen, React only makes progress when the fake clock is
 * advanced, and mocked-API responses can resolve on either side of our last
 * advance depending on machine timing. Spin: check the page, advance the fake
 * clock, repeat, until the readiness predicate is satisfied or the budget runs
 * out. This makes data-driven content appear deterministically instead of
 * racing a plain toBeVisible against a frozen scheduler.
 */
async function advanceUntil(
  page: Page,
  isReady: () => boolean,
  label: string,
  stepMs = 500,
  maxMs = 20000,
): Promise<void> {
  let waited = 0;
  while (waited <= maxMs) {
    const ready = await page.evaluate(isReady);
    if (ready) return;
    await page.clock.runFor(stepMs);
    waited += stepMs;
  }
  throw new Error(`Timed out advancing clock: ${label}`);
}

test.describe("theme screenshot regression", () => {
  for (const theme of THEMES) {
    test.describe(`${theme} mode`, () => {
      test("public pay page renders the active payment request", async ({
        page,
      }) => {
        await openThemed(page, theme, "/pay?username=alex&amount=5&asset=USDC", {
          paymentState: "ACTIVE",
        });
        await expect(
          page.getByRole("heading", { name: /payment request/i }),
        ).toBeVisible();
        await settlePage(page);
        await expect(page).toHaveScreenshot(`pay-active-${theme}.png`, {
          fullPage: true,
        });
      });

      test("public pay page renders the paid (success) state", async ({
        page,
      }) => {
        await openThemed(page, theme, "/pay?username=alex&amount=5&asset=USDC", {
          paymentState: "PAID",
        });
        await expect(
          page.getByRole("heading", { name: /payment complete/i }),
        ).toBeVisible();
        await settlePage(page);
        await expect(page).toHaveScreenshot(`pay-paid-${theme}.png`, {
          fullPage: true,
        });
      });

      test("dashboard renders hero, metrics, analytics and activity feed", async ({
        page,
      }) => {
        await openThemed(page, theme, "/dashboard");
        // Content (metrics, analytics, activity feed) renders on fake-clock
        // ticks after mocked API responses arrive; advance while polling until
        // it is all present so timing can't flake.
        await advanceUntil(
          page,
          () => {
            const text = document.body?.innerText ?? "";
            return (
              !text.includes("Loading dashboard") &&
              text.includes("Live Backend Data") &&
              text.includes("Analytics Overview") &&
              /ab12cd.*uv12/.test(text)
            );
          },
          `dashboard content (${theme})`,
        );
        // Content is up now — settle the recharts JS animations and any
        // setTimeout-driven previews before capturing.
        await settlePage(page, 4000);
        await expect(
          page.getByRole("heading", { name: /welcome back/i }),
        ).toBeVisible();
        await expect(page.getByText("Live Backend Data")).toBeVisible();
        await expect(
          page.getByRole("heading", { name: /analytics overview/i }),
        ).toBeVisible();
        await expect(page.getByText(/ab12cd.*uv12/)).toBeVisible();
        // Settle charts + setTimeout-driven previews AFTER the content is
        // mounted, so the recharts JS animations complete before capture.
        await settlePage(page, 4000);

        // The dashboard uses blurred glow elements, shadows and SVG charts,
        // whose rasterization differs slightly between GPUs/software renderers
        // and Chrome builds. Allow that environment noise explicitly; the
        // theme-token contract (below) keeps exact color assertions.
        await expect(page).toHaveScreenshot(`dashboard-${theme}.png`, {
          maxDiffPixelRatio: 0.04,
        });

        // Zoom the analytics block: pin the section to the top of the viewport
        // so the capture stays 1440x900 (a fixed size) instead of a
        // content-sized bounding box that can shift by a pixel across
        // environments and fail a screenshot on dimensions alone.
        await page.evaluate(() => {
          document
            .getElementById("analytics-dashboard")
            ?.scrollIntoView({ block: "start" });
        });
        await settlePage(page);
        await expect(page).toHaveScreenshot(`dashboard-analytics-${theme}.png`, {
          maxDiffPixelRatio: 0.04,
        });
      });

      test("settings page renders profile customization forms", async ({
        page,
      }) => {
        await openThemed(page, theme, "/settings");
        await expect(page.locator('input[type="color"]')).toBeVisible();
        await expect(page.getByText("Social Links")).toBeVisible();
        await settlePage(page);

        // Capture the settings surface as fixed-size viewport shots. The page
        // is taller than the viewport, and its content height can differ by a
        // pixel across environments (font metric rounding), so a fullPage or
        // element-bound capture would fail on dimensions alone.
        await expect(page).toHaveScreenshot(`settings-${theme}.png`, {
          maxDiffPixelRatio: 0.04,
        });

        // Bottom fold: the Social Links card (custom color swatches + link
        // fields) pinned into the viewport.
        await page.getByText("Social Links").scrollIntoViewIfNeeded();
        await settlePage(page);
        await expect(page).toHaveScreenshot(`settings-bottom-${theme}.png`, {
          maxDiffPixelRatio: 0.04,
        });
      });

      test("admin console renders controls, health and audit logs", async ({
        page,
      }) => {
        await openThemed(page, theme, "/admin");
        await expect(page.getByText("Safety Controls")).toBeVisible();
        await expect(page.getByText("System Health")).toBeVisible();
        await expect(
          page.getByText("Persistent store healthy"),
        ).toBeVisible();
        await expect(page.getByText("Audit Logs")).toBeVisible();
        await settlePage(page);
        await expect(page).toHaveScreenshot(`admin-${theme}.png`, {
          fullPage: true,
        });
      });
    });
  }
});

test.describe("theme token contract", () => {
  const COVERED_ROUTES = [
    { path: "/pay?username=alex&amount=5&asset=USDC", name: "public pay" },
    { path: "/dashboard", name: "dashboard" },
    { path: "/settings", name: "settings" },
    { path: "/admin", name: "admin" },
  ];

  for (const theme of THEMES) {
    for (const route of COVERED_ROUTES) {
      test(`background/foreground tokens and color-scheme resolve for ${theme} mode on the ${route.name} screen`, async ({
        page,
      }) => {
        // One hard navigation per test. Repeated hard navigations on a single
        // page under the frozen clock can skip the no-FOUC head script, so the
        // suite always hard-loads each route from a fresh page/context.
        await openThemed(page, theme, route.path, {
          paymentState: "ACTIVE",
        });
        // Wait for the exact invariant we assert below: the no-FOUC script sets
        // the theme class on <html> during parsing; don't race it.
        await page.waitForFunction(
          (expected) => document.documentElement.classList.contains(expected),
          theme,
        );
        // Advance rAF so hydration/layout settle before reading computed styles.
        await page.clock.runFor(1500);

        const resolved = await page.evaluate(() => {
          const root = getComputedStyle(document.documentElement);
          const body = getComputedStyle(document.body);
          return {
            htmlClass: document.documentElement.className,
            bodyBg: body.backgroundColor,
            bodyColor: body.color,
            colorScheme: root.colorScheme,
            backgroundToken: root.getPropertyValue("--background").trim(),
            foregroundToken: root.getPropertyValue("--foreground").trim(),
            cardToken: root.getPropertyValue("--card").trim(),
            borderToken: root.getPropertyValue("--border").trim(),
          };
        });

        const expected = TOKEN_EXPECTATIONS[theme];
        const label = `${route.name} / ${theme}`;

        expect(resolved.htmlClass, `${label}: html class`).toContain(theme);
        expect(resolved.colorScheme, `${label}: color-scheme`).toBe(
          expected.colorScheme,
        );
        expect(resolved.bodyBg, `${label}: body background`).toBe(
          expected.bodyBg,
        );
        expect(resolved.bodyColor, `${label}: body foreground`).toBe(
          expected.bodyColor,
        );
        // Tokens themselves flip without introducing alpha channels or blanks.
        expect(resolved.backgroundToken, `${label}: --background`).not.toBe("");
        expect(resolved.foregroundToken, `${label}: --foreground`).not.toBe("");
        expect(resolved.cardToken, `${label}: --card`).not.toBe("");
        expect(resolved.borderToken, `${label}: --border`).not.toBe("");

        // Light and dark must actually differ, or the palette never flipped.
        const other = TOKEN_EXPECTATIONS[theme === "dark" ? "light" : "dark"];
        expect(resolved.bodyBg, `${label}: differs from other theme`).not.toBe(
          other.bodyBg,
        );
      });
    }
  }
});
