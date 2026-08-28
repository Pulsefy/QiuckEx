import { expect, test } from "@playwright/test";

/**
 * FE-67 — End-to-end coverage for the pay → receipt path.
 *
 * Walks the core revenue path in a real browser:
 *   1. create a payment link from the generator,
 *   2. open the public pay page and complete a testnet payment,
 *   3. assert the receipt renders and its reference + status match the backend.
 *
 * Flake mitigation: every step waits on application state via Playwright's
 * web-first assertions and `waitForResponse`, never fixed sleeps. On failure
 * the config captures a screenshot + trace artifact.
 */
test("create a payment link, pay on testnet, and see the receipt", async ({
  page,
}) => {
  // 1. Create a payment link.
  await page.goto("/generator");
  await page.getByLabel(/amount/i).fill("5");
  await page.getByRole("button", { name: /create (payment )?link/i }).click();

  // The link creation call resolves before we navigate.
  const linkResponse = await page.waitForResponse(
    (res) => res.url().includes("/links") && res.request().method() === "POST",
  );
  const { reference, url } = await linkResponse.json();
  expect(reference).toBeTruthy();

  // 2. Open the public pay page and complete the payment.
  await page.goto(url ?? `/pay/${reference}`);
  await expect(page.getByRole("heading", { name: /pay/i })).toBeVisible();
  await page.getByRole("button", { name: /pay|confirm|send/i }).click();

  // Wait on the payment settlement response rather than a timer.
  const payResponse = await page.waitForResponse(
    (res) =>
      res.url().includes("/transactions") || res.url().includes("/payments"),
  );
  const settlement = await payResponse.json();

  // 3. Assert the receipt renders and matches the backend response.
  await expect(page).toHaveURL(/receipt|success/i);
  await expect(page.getByText(/receipt|paid|success/i)).toBeVisible();

  const receiptRef = page.getByTestId("receipt-reference");
  await expect(receiptRef).toContainText(String(settlement.reference ?? reference));

  const receiptStatus = page.getByTestId("receipt-status");
  await expect(receiptStatus).toContainText(
    new RegExp(String(settlement.status ?? "paid"), "i"),
  );
});
