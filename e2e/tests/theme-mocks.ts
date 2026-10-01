import type { Page } from "@playwright/test";

/**
 * FE-56 — Deterministic backend fixtures for the theme regression suite.
 *
 * Visual regression only works when every screen renders byte-identical
 * content on every run. The app talks to a real backend (payment links,
 * analytics, activity feed, admin controls), so this module intercepts those
 * calls with fixed fixtures and registers them against the browser.
 *
 * All dates are chosen relative to FIXED_TIME so relative labels ("2h ago",
 * countdowns, ...) are stable. Nothing here is a real user or transaction.
 */

/** Clock value the app is frozen at for every screenshot (UTC). */
export const FIXED_TIME = "2026-01-15T12:00:00.000Z";

export type PaymentStateFixture = "ACTIVE" | "PAID";

/** Public-link fixture shared by both payment states. */
function paymentStatusBase() {
  return {
    username: "alex",
    amount: "5",
    asset: "USDC",
    memo: "Coffee sync",
    destinationPublicKey:
      "GD6FIYQAA5PAYMENTDESTINATIONACCOUNTPUBLICKEYQ32BZ4ZFTXO7",
  };
}

/** Active payment link — the idle public pay page. */
function activePaymentStatus() {
  return {
    state: "ACTIVE",
    ...paymentStatusBase(),
    expiresAt: "2026-01-15T18:00:00.000Z",
    transactionHash: null,
    paidAt: null,
    swapOptions: [
      {
        sourceAmount: "5.01",
        sourceAsset: "XLM",
        destinationAmount: "5",
        destinationAsset: "USDC",
        hopCount: 1,
        pathHops: ["XLM", "USDC"],
        rateDescription: "Best rate via XLM path",
      },
    ],
    acceptsMultipleAssets: true,
    acceptedAssets: ["USDC", "XLM"],
    userMessage: "Please send 5 USDC to @alex",
    availableActions: ["pay"],
  };
}

/** Paid payment link — the payment-success public page. */
function paidPaymentStatus() {
  return {
    state: "PAID",
    ...paymentStatusBase(),
    expiresAt: null,
    transactionHash:
      "f37bbd8f5f49e6c1c71a4e0f9b1234567890abcdef01234567890abcdef0123",
    paidAt: "2026-01-15T11:58:24.000Z",
    swapOptions: null,
    acceptsMultipleAssets: false,
    acceptedAssets: null,
    userMessage: "Payment completed successfully!",
    availableActions: [],
  };
}

/** `/analytics/report` response (ApiReport shape consumed by analyticsApi.ts). */
function analyticsReport() {
  return {
    summary: {
      totalTransactions: 128,
      successfulTransactions: 121,
      failedTransactions: 7,
      conversionRate: 94.5,
      totalVolumeUsd: 42750,
      averageTransactionUsd: 334,
    },
    assetDistribution: [
      { asset: "USDC", volumeUsd: 27400, percentage: 64, transactionCount: 80 },
      { asset: "XLM", volumeUsd: 15350, percentage: 36, transactionCount: 48 },
    ],
    timeSeries: [
      ["2026-01-15", 14, 13, 1500, { USDC: 1000, XLM: 500 }],
      ["2026-01-14", 12, 11, 1300, { USDC: 800, XLM: 500 }],
      ["2026-01-13", 18, 17, 2400, { USDC: 1600, XLM: 800 }],
      ["2026-01-12", 9, 9, 900, { USDC: 900, XLM: 0 }],
      ["2026-01-11", 21, 20, 3100, { USDC: 2100, XLM: 1000 }],
      ["2026-01-10", 11, 10, 1800, { USDC: 1200, XLM: 600 }],
      ["2026-01-09", 7, 7, 700, { USDC: 700, XLM: 0 }],
      ["2026-01-08", 16, 15, 2900, { USDC: 1900, XLM: 1000 }],
      ["2026-01-07", 10, 9, 1200, { USDC: 800, XLM: 400 }],
      ["2026-01-06", 5, 5, 500, { USDC: 500, XLM: 0 }],
    ].map(
      ([period, transactionCount, successfulTransactions, volumeUsd, assetVolumes]) => ({
        period,
        transactionCount,
        successfulTransactions,
        volumeUsd,
        assetVolumes,
      }),
    ),
  };
}

/** `/payments/recent` response consumed by the dashboard activity feed. */
function recentPayments() {
  return {
    items: [
      {
        hash: "ab12cd34ef56gh78ij90kl12mn34op56qr78st90uv12",
        amount: "5",
        assetCode: "USDC",
        memo: "Coffee sync",
        timestamp: "2026-01-15T11:59:20.000Z",
        sourceAccount: "GA7E8FQ92WE1R5T6Y7U8I9O0P1A2S3D4F5G6H7J8K9L0",
        destinationAccount:
          "GD6FIYQAA5PAYMENTDESTINATIONACCOUNTPUBLICKEYQ32BZ4ZFTXO7",
      },
      {
        hash: "cd34ef56gh78ij90kl12mn34op56qr78st90uv12wx34",
        amount: "12",
        assetCode: "USDC",
        memo: "Invoice #1042",
        timestamp: "2026-01-15T10:00:00.000Z",
        sourceAccount: "GC4MNP2QWE1R5T6Y7U8I9O0P1A2S3D4F5G6H7J8K9L0Q1",
        destinationAccount:
          "GD6FIYQAA5PAYMENTDESTINATIONACCOUNTPUBLICKEYQ32BZ4ZFTXO7",
      },
      {
        hash: "ef56gh78ij90kl12mn34op56qr78st90uv12wx34yz56ab",
        amount: "120",
        assetCode: "XLM",
        memo: null,
        timestamp: "2026-01-12T08:00:00.000Z",
        sourceAccount: "GD2JKL2QWE1R5T6Y7U8I9O0P1A2S3D4F5G6H7J8K9L0QW",
        destinationAccount:
          "GD6FIYQAA5PAYMENTDESTINATIONACCOUNTPUBLICKEYQ32BZ4ZFTXO7",
      },
      {
        hash: "gh78ij90kl12mn34op56qr78st90uv12wx34yz56ab78cd90",
        amount: "1",
        assetCode: "USDC",
        memo: "Tip",
        timestamp: "2026-01-08T00:00:00.000Z",
        sourceAccount: "GB9OPQ2QWE1R5T6Y7U8I9O0P1A2S3D4F5G6H7J8K9L0QE",
        destinationAccount:
          "GD6FIYQAA5PAYMENTDESTINATIONACCOUNTPUBLICKEYQ32BZ4ZFTXO7",
      },
    ],
    total: 4,
    next_cursor: null,
    has_more: false,
  };
}

/** `/admin/feature-flags` response (FeatureFlags + SystemHealth panels). */
function adminFeatureFlags() {
  return {
    flags: [
      {
        key: "instant-settlement",
        name: "Instant Settlement",
        description: "Route eligible payments through the instant settlement path.",
        enabled: true,
        killSwitch: false,
        rolloutPercentage: 100,
        environments: ["staging", "production"],
        updatedAt: "2026-01-15T10:05:00.000Z",
        updatedBy: "ops-team",
      },
      {
        key: "xray-privacy",
        name: "X-Ray Privacy",
        description: "Enable shielded transactions via the privacy contract.",
        enabled: true,
        killSwitch: false,
        rolloutPercentage: 100,
        environments: ["testnet", "mainnet"],
        updatedAt: "2026-01-15T10:05:00.000Z",
        updatedBy: "ops-team",
      },
      {
        key: "new-link-generator",
        name: "New Link Generator",
        description: "Gradual rollout of the redesigned link generator.",
        enabled: false,
        killSwitch: true,
        rolloutPercentage: 15,
        environments: ["staging"],
        updatedAt: "2026-01-15T10:05:00.000Z",
        updatedBy: "platform-eng",
      },
    ],
    source: "cache",
    storeAvailable: true,
  };
}

/** `/admin/audit` response (AuditLogs panel). */
function adminAuditLogs() {
  return {
    data: [
      {
        id: "audit-1",
        action: "FEATURE_FLAG_UPDATED",
        actor: "ops-team",
        target: "xray-privacy",
        metadata: { after: { enabled: true } },
        createdAt: "2026-01-15T10:05:00.000Z",
      },
      {
        id: "audit-2",
        action: "FEATURE_FLAG_UPDATED",
        actor: "platform-eng",
        target: "new-link-generator",
        metadata: { after: { killSwitch: true } },
        createdAt: "2026-01-15T09:12:00.000Z",
      },
      {
        id: "audit-3",
        action: "USER_ROLE_CHANGED",
        actor: "ops-team",
        target: "alex",
        metadata: {},
        createdAt: "2026-01-14T18:44:00.000Z",
      },
    ],
  };
}

/** `/admin/rc-validation/report` response consumed by TestnetHealthConsole. */
function adminHealthReport() {
  return {
    reportId: "rc-theme-001",
    generatedAt: FIXED_TIME,
    network: "testnet",
    environment: "staging",
    releaseReady: false,
    overallStatus: "blocked",
    sections: {
      smoke: {
        status: "warning",
        ready: false,
        checks: [
          { name: "horizon", status: "up" },
          {
            name: "soroban-rpc",
            status: "degraded",
            error: "Elevated latency",
          },
        ],
        passed: 1,
        failed: 0,
      },
      registry: {
        status: "fail",
        network: "testnet",
        authoritative: true,
        version: 12,
        activeContracts: 1,
        expectedContracts: ["quickex", "escrow"],
        missingContracts: ["escrow"],
      },
      lag: {
        status: "warning",
        currentNetworkLedger: 543210,
        lastIndexedLedger: 543172,
        lagLedgers: 38,
        isLagging: true,
        isBlocking: false,
        thresholdLedgers: 100,
      },
      environment: {
        status: "warning",
        checks: [
          {
            check: "network_configuration",
            status: "pass",
            details: "Network: testnet",
          },
          {
            check: "contract_registry",
            status: "warning",
            details: "Escrow deployment pending",
          },
        ],
        passed: 1,
        failed: 0,
        warnings: 1,
      },
    },
    blockers: [
      {
        id: "registry.missing-contracts",
        severity: "critical",
        category: "registry",
        message: "Registry is missing expected contract(s): escrow",
        remediation: "Publish the missing contract deployment(s) to the registry",
        detectedAt: FIXED_TIME,
      },
      {
        id: "lag.lagging",
        severity: "warning",
        category: "lag",
        message: "Indexer is 38 ledgers behind the network head",
        remediation: "Confirm ingestion is catching up before release",
        detectedAt: FIXED_TIME,
      },
      {
        id: "environment.contract_registry.warning",
        severity: "info",
        category: "environment",
        message: "Environment parity reports a pending escrow deployment",
        remediation: "Verify staging deployment metadata",
        detectedAt: FIXED_TIME,
      },
    ],
    summary: { critical: 1, warning: 1, info: 1 },
  };
}

export type ThemeMockOptions = {
  /** Which payment-link state `/pay` should render. Defaults to ACTIVE. */
  paymentState?: PaymentStateFixture;
};

/**
 * Register all backend mocks for the current page. Matching is by URL so the
 * same fixture set works for every screen; a catch-all returns a 501 so no
 * unhandled backend call can hang a screenshot.
 */
export async function mockBackend(
  page: Page,
  options: ThemeMockOptions = {},
): Promise<void> {
  const jsonResponse = (body: unknown) => ({
    status: 200,
    contentType: "application/json" as const,
    body: JSON.stringify(body),
  });

  const paymentStatus =
    options.paymentState === "PAID"
      ? paidPaymentStatus()
      : activePaymentStatus();

  // Catch-all FIRST: when several routes match a URL, Playwright uses the
  // most recently registered handler, so this must be the first route added —
  // otherwise it would swallow the specific mocks registered below. Anything
  // that slips past the specific patterns gets a 501 instead of hanging on the
  // network.
  await page.route("**://api.quickex.test/**", (route) =>
    route.fulfill({ status: 501, body: '{"error":"unmocked"}' }),
  );

  await page.route("**/v1/network/bootstrap**", (route) =>
    route.fulfill(jsonResponse({})),
  );
  await page.route("**/feature-flags/snapshot**", (route) =>
    route.fulfill(jsonResponse({ flags: [] })),
  );
  await page.route("**/payment-links/status**", (route) =>
    route.fulfill(jsonResponse(paymentStatus)),
  );
  await page.route("**/analytics/report**", (route) =>
    route.fulfill(jsonResponse(analyticsReport())),
  );
  await page.route("**/payments/recent**", (route) =>
    route.fulfill(jsonResponse(recentPayments())),
  );
  await page.route("**/admin/audit**", (route) =>
    route.fulfill(jsonResponse(adminAuditLogs())),
  );
  await page.route("**/admin/feature-flags/**", (route) =>
    route.fulfill(jsonResponse(adminFeatureFlags().flags[0])),
  );
  await page.route("**/admin/feature-flags**", (route) =>
    route.fulfill(jsonResponse(adminFeatureFlags())),
  );
  await page.route("**/admin/rc-validation/report**", (route) =>
    route.fulfill(jsonResponse(adminHealthReport())),
  );
  await page.route("**/health**", (route) =>
    route.fulfill(jsonResponse({ status: "ok", uptime: 60 })),
  );
}
