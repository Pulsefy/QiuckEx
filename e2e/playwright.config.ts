import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright config for the QuickEx pay→receipt E2E (FE-67).
 *
 * `BASE_URL` points at the preview / ephemeral environment under test in CI.
 * Traces and screenshots are captured on first retry so failures are
 * debuggable; flake mitigation relies on Playwright's web-first assertions
 * (auto-waiting on state) rather than fixed sleeps.
 */
export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  retries: process.env.CI ? 2 : 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: process.env.BASE_URL ?? "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
