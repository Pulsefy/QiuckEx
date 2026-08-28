# Frontend Performance & Offline

This document covers the frontend performance guardrails and offline strategy
introduced in FE-64…FE-67.

## Service Worker & Offline Caching (FE-64)

The service worker (`app/frontend/public/sw.js`) applies a deliberate strategy
per asset class. The routing logic is mirrored (and unit-tested) in
`app/frontend/src/lib/sw-cache-strategy.ts`:

| Asset class                        | Strategy          | Rationale                                  |
| ---------------------------------- | ----------------- | ------------------------------------------ |
| Payment-critical API (`/api/payments`, `/api/links`, `/api/transactions`, `/api/receipts`, `/api/pay*`) | **network-only**  | Never serve stale money-related data       |
| Other API reads (`/api/*`)         | network-first     | Fresh-first, cache as a resilience fallback |
| Hashed static assets (`/_next/static/`, images, fonts) | cache-first       | Immutable — safe to serve from cache        |
| Navigations                        | network, else `/offline` | Predictable offline route                   |

Caches are **versioned** (`CACHE_VERSION`); the `activate` handler deletes any
cache whose name doesn't match the current version, so a deploy invalidates old
entries without a hard reload. Register the worker from a client component via
`registerServiceWorker()` (`src/lib/register-sw.ts`); it no-ops outside
production.

### Manual offline check

1. `npm run build && npm run start` in `app/frontend`.
2. Load the app, then in DevTools → Application → Service Workers confirm the
   worker is activated.
3. Switch DevTools → Network to **Offline** and navigate to a new route — the
   `/offline` page renders instead of a browser error.

## Bundle-Size Budgets (FE-65)

Per-route first-load JS is measured during CI (`build` job) by
`scripts/bundle-budget.mjs` and enforced against `app/frontend/bundle-budgets.json`.
CI fails when a route exceeds its budget beyond the configured `tolerance`, and
prints the size delta against the base branch.

**Adjusting a budget deliberately:** edit the route's `maxBytes` in
`bundle-budgets.json` in the same PR that grows the route, with a note in the PR
description explaining why. Prefer code-splitting or trimming dependencies
before raising a budget.

## Core Web Vitals (FE-66)

`frontend-web-vitals.yml` builds the app in **production** mode, serves it, and
runs Lighthouse (`scripts/collect-vitals.mjs`) to measure **LCP, CLS, INP** for
`/pay`, `/receipt`, and `/dashboard`. `scripts/web-vitals.mjs` evaluates the
results against the web.dev thresholds (classification mirrored and unit-tested
in `src/lib/vitals-thresholds.ts`) and reports a delta against the base branch.

**Policy:** a metric landing in the **poor** band fails the build by default;
pass `--flag-only` to downgrade to a non-blocking flag.

## End-to-End: Pay → Receipt (FE-67)

`e2e/` contains a Playwright suite that walks link creation → testnet payment →
receipt (`e2e/tests/pay-to-receipt.spec.ts`), asserting the receipt reference
and status match the backend response. It runs in CI (`frontend-e2e.yml`)
against a preview/ephemeral environment, uploads screenshots + traces on
failure, and relies on web-first assertions (no fixed sleeps) for stability.
