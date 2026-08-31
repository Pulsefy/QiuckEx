import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

/**
 * #766 — Automated accessibility audits for the QR/payment flow.
 *
 * Runs axe-core against the payment link generator and the public pay page
 * (the same two screens exercised by pay-to-receipt.spec.ts) and fails on
 * any WCAG 2.0/2.1 A or AA violation. Only serious/critical severities fail
 * the build for now, so noisy low-impact rules don't block unrelated PRs
 * while real barriers (missing labels, bad contrast, unreachable controls)
 * still gate CI.
 */

function seriousOrCriticalViolations(results: Awaited<ReturnType<AxeBuilder["analyze"]>>) {
  return results.violations.filter(
    (violation) => violation.impact === "serious" || violation.impact === "critical",
  );
}

test("payment link generator has no serious/critical a11y violations", async ({
  page,
}) => {
  await page.goto("/generator");
  await expect(page.getByRole("button", { name: /generate payment link/i })).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();

  expect(seriousOrCriticalViolations(results)).toEqual([]);
});

test("public pay page has no serious/critical a11y violations", async ({
  page,
}) => {
  await page.goto("/generator");
  await page.getByLabel(/amount/i).fill("5");
  await page.getByRole("button", { name: /generate payment link/i }).click();

  const linkResponse = await page.waitForResponse(
    (res) => res.url().includes("/links") && res.request().method() === "POST",
  );
  const { reference, url } = await linkResponse.json();

  await page.goto(url ?? `/pay/${reference}`);
  await expect(page.getByRole("heading", { name: /pay/i })).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();

  expect(seriousOrCriticalViolations(results)).toEqual([]);
});
