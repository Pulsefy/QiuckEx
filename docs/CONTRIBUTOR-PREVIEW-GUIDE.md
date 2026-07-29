# Contributor Preview Environments Guide

This guide explains how QuickEx preview environments work, how to use them, and how to troubleshoot common issues. It covers the full lifecycle from creation through cleanup, branch metadata conventions, diagnostics tooling, and testnet safety safeguards.

---

## 1. Preview Environment Lifecycle

### What Preview Environments Are

Preview environments are isolated, ephemeral deployments that mirror a contributor's branch state. Each preview consists of:

- **Frontend preview** — Vercel deployment with a unique URL per PR
- **Backend preview** — branch-scoped API environment mapped via the `BranchPreviewService`
- **Preview scope** — data isolation layer via `PreviewScopeService` (Supabase-backed, with TTL-based expiry)

Previews enable contributors, reviewers, and QA to validate changes against a live, network-isolated stack without affecting staging or production.

### When Previews Are Created

| Trigger | What Happens |
|---|---|
| Pull Request opened against `main` | Vercel auto-deploys the frontend preview. GitHub Actions runs CI checks (type-check, lint, build) via `.github/workflows/frontend-ci.yml` and `.github/workflows/ci.yml`. |
| New commits pushed to a PR branch | Vercel re-deploys the frontend. The branch preview mapping (if already registered) retains its URLs but the served code reflects the latest commit. |
| Admin registers a backend preview | An API key holder calls `POST /admin/branch-previews` to wire the branch name to specific API/frontend URLs and network settings. |

Refer to the deployment playbooks in:
- [VERCEL_DEPLOYMENT_GUIDE.md](../app/frontend/VERCEL_DEPLOYMENT_GUIDE.md) for the frontend preview setup
- [cd.yml](../.github/workflows/cd.yml) for the production CD pipeline (main branch only)
- [deploy-app action](../.github/actions/deploy-app/action.yml) for the backend deploy + health-check composite action

### Who Owns a Preview Environment

- The **PR author** is the primary owner and is responsible for monitoring preview health and cleaning up unused resources.
- **Shared previews** (`isShared: true`) are owned by the team and never auto-expired.
- Previews may be reassigned or marked `expiryExempt: true` by an admin through the branch preview admin endpoints.

### Contributor Responsibilities

1. Verify the preview URL and network before sharing links or running integration tests.
2. Do not store production credentials or real funds in any preview-scoped data.
3. Close / comment on PRs promptly so automated cleanup can reclaim resources.
4. Report stale or misconfigured previews to an admin for cache invalidation or re-mapping.
5. Use the diagnostics panel and runtime endpoints to confirm configuration before testing.

### Expected Lifecycle Stages

```
Creation → Usage/Testing → Updates on New Commits → Cleanup / Expiry
```

1. **Creation** — PR opens, Vercel provisions the frontend preview, admin (or automation) registers the branch via `POST /admin/branch-previews` with a `ttlMs`, API URL, frontend URL, network, and contract registry version. A preview scope row is inserted into `preview_scopes` with a 7-day default TTL (see `DEFAULT_PREVIEW_TTL_MS` in [preview-scope.types.ts](../app/backend/src/preview-scope/preview-scope.types.ts)).
2. **Usage / Testing** — Contributors open the Vercel URL, the diagnostics panel loads, API calls route through the mapped backend, and preview-scoped data is isolated per scope.
3. **Updates after new commits** — Each push re-triggers Vercel builds. The backend mapping is not recreated automatically; if the API URL itself changes an admin must call `PUT /admin/branch-previews/:id`. The LRU cache (max 1000 entries, default 7-day TTL) is invalidated on every update so new values take effect on the next lookup.
4. **Cleanup / removal** — Automated hourly sweep deactivates stale previews; on PR merge the mapping is typically deleted by an admin or left to auto-expiry. All preview-scoped data is purged via the `delete_expired_preview_scope_data` Supabase RPC (see `cleanupExpiredScope` in [preview-scope.service.ts](../app/backend/src/preview-scope/preview-scope.service.ts)).

---

## 2. Branch Preview Metadata

### Branch Naming Expectations

Follow the conventions defined in the root [CONTRIBUTING.md](../CONTRIBUTING.md):

| Prefix | Purpose | Example |
|---|---|---|
| `feat/` | New feature work | `feat/recurring-payment-ui` |
| `fix/` | Bug fixes | `fix/escrow-balance-decimals` |
| `docs/` | Documentation-only changes | `docs/contributor-preview-guide` |
| `chore/` | Maintenance, tooling, refactors | `chore/bump-soroban-sdk` |

Branch names are normalized to lowercase + trimmed before cache/database lookup (see `getPreviewForBranch` in [branch-preview.service.ts](../app/backend/src/branch-preview/branch-preview.service.ts)). Avoid spaces, non-ASCII characters, and excessively long names.

### How Branch Information Appears in Previews

**Frontend (Vercel deployment metadata):**

The `getDeploymentInfo()` helper in [deployment-info.ts](../app/frontend/src/lib/deployment-info.ts) surfaces:

| Field | Source Env Var | Example |
|---|---|---|
| `branch` | `NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF` | `feat/preview-diagnostics` |
| `commitSha` | `NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA` | `abcdef1234567890abcdef1234567890abcdef12` |
| `commitShort` | Derived from commitSha (first 7 chars) | `abcdef1` |
| `deployedAt` | `NEXT_PUBLIC_VERCEL_DEPLOYED_AT` (injected by CI) | `2026-07-23T15:00:00Z` |
| `vercelEnv` | `NEXT_PUBLIC_VERCEL_ENV` | `preview` / `production` / `development` |
| `vercelUrl` | `NEXT_PUBLIC_VERCEL_URL` | `quickex-abc123.vercel.app` |

**Backend (branch preview mapping):**

Call `GET /preview/:branchName` (public, rate-limited) to retrieve:

```json
{
  "branchName": "feat/contributor-guide",
  "apiUrl": "https://preview-api.quickex.to",
  "frontendUrl": "https://quickex-feat-contributor-guide.vercel.app",
  "network": "testnet",
  "contractRegistryVersion": "v2.3.1",
  "isFallback": false
}
```

When `isFallback: true`, the branch is unknown, inactive, or expired, and the system routed you to `FALLBACK_API_URL` / `FALLBACK_FRONTEND_URL` (see [env.schema.ts](../app/backend/src/config/env.schema.ts)). Always check this flag before reporting a bug.

### Preview Identifiers, Labels, and URLs

- **Vercel Preview URL format:** `https://<project-name>-<git-branch-slug>-<random>.vercel.app`
- **Backend preview mapping URL lookup:** `GET /preview/:branchName`
- **Preview scope header:** `x-preview-scope` (see `PREVIEW_SCOPE_HEADER` in [preview-scope.types.ts](../app/backend/src/preview-scope/preview-scope.types.ts)). Endpoints decorated with `@PreviewScope()` require a valid, non-expired scope ID in this header; otherwise the `PreviewScopeGuard` returns a 403.
- **Admin audit trail:** All create/update/delete/invalidate/cleanup actions on branch previews are logged via `AuditService` (look for events `branch_preview.created`, `branch_preview.updated`, `branch_preview.auto_expired`, etc.).

### Preview Banners and Environment Indicators

The **diagnostics panel** is conditionally rendered using `isDiagnosticsPanelVisible()` from [deployment-info.ts](../app/frontend/src/lib/deployment-info.ts). The visibility rule is:

> Show panel **UNLESS** `vercelEnv === "production"` **AND** `network === "mainnet"`.

This means contributors always see the panel in:
- Local development (`vercelEnv = null`)
- Vercel previews (`vercelEnv = "preview"`)
- Testnet production deployments (`network = "testnet"`)

The panel is hidden **only** on a live mainnet production deployment so end users never see it.

To inspect the panel manually from the browser console:

```js
// Exposed via Next.js pageProps on SSR pages
window.__NEXT_DATA__.props.pageProps.deploymentInfo

// Or call the pure helper (imported by components)
// getDeploymentInfo()
```

---

## 3. Diagnostics Panels and Debugging Information

### Available Diagnostics Tools

| Tool | Where to Access It |
|---|---|
| Frontend Deployment Diagnostics Panel | Footer / dev overlay on every non-mainnet-production page. See `isDiagnosticsPanelVisible()`. |
| Backend Shallow Health | `GET /health` — liveness probe. |
| Backend Deep Readiness | `GET /ready` — dependency checks (Supabase, Horizon, Soroban RPC, queue, migrations, ingestion, env). |
| Backend Public Status Page | `GET /status` — cacheable, rate-limited (5/min) status suitable for a status badge. |
| Branch Preview Lookup | `GET /preview/:branchName` — resolve mapping + fallback flag. |
| Network Snapshot | `GET /v1/network` — resolved network, passphrase, horizon/soroban-rpc/explorer URLs (see [network.config.ts](../app/backend/src/config/network.config.ts)). |
| Preview Scope Validation | Check response for `403 Forbidden` with message `Preview scope is required` / `Preview scope is invalid or expired` from `PreviewScopeGuard`. |

### What Information Contributors Can Inspect

#### Deployment Status & Version

From `/health` ([health.controller.ts](../app/backend/src/health/health.controller.ts)):

```json
{
  "status": "ok",
  "version": "0.1.0",
  "uptime": 1842
}
```

From the frontend diagnostics panel / `getDeploymentInfo()`:
- Branch name, full and short commit SHA, build timestamp (`deployedAt`)
- Vercel environment tier + URL
- App version, contract registry version

#### Environment Configuration

From `/ready` ([health.service.ts](../app/backend/src/health/health.service.ts)) the `environment` check reports:

```json
{
  "name": "environment",
  "status": "up",
  "details": [
    "Database configuration loaded",
    "Network: testnet",
    "Horizon configuration ready",
    "Payment signing configured"
  ]
}
```

Critical env vars that determine preview behavior (see [env.schema.ts](../app/backend/src/config/env.schema.ts)):
- `NETWORK` / `STELLAR_NETWORK` — `testnet` | `mainnet`. Conflicting values abort startup.
- `FALLBACK_API_URL` / `FALLBACK_FRONTEND_URL` — fallback when a branch mapping is missing.
- `CORS_VERCEL_PROJECT` — automatically allows `https://<slug>-*.vercel.app` origins for previews.
- `PREVIEW_INACTIVITY_THRESHOLD_MS` / `PREVIEW_MAX_AGE_MS` — auto-expiry windows.

#### Service Health

The `/ready` endpoint returns individual check results with latency and error details:

| Check | What It Validates |
|---|---|
| `supabase` | Supabase connectivity (3s timeout). Ping + latency. |
| `migrations` | `schema_migrations` table accessibility; falls back to critical-table probe. |
| `queue` | Jobs DB table queryable (5s timeout). |
| `horizon` | HTTP HEAD to the resolved Horizon base URL. |
| `soroban_rpc` | Calls Soroban RPC `getNetworkPassphrase` via `SorobanRpcService`. |
| `ingestion` | Contract-event cursor readability; lag tracking. |
| `environment` | Env-var completeness, network, signing keys. |

Overall `ready: true` requires supabase + migrations + queue + horizon to all be `up`.

#### Logs and Errors

- Backend audit events for preview operations are written via `AuditService`. Search for event names:
  - `branch_preview.created`, `branch_preview.updated`, `branch_preview.deleted`
  - `branch_preview.cache_invalidated`, `branch_preview.cache_cleared`
  - `branch_preview.auto_expired` (actor `system:preview-auto-expiry-worker`)
  - `network_safety_gate.blocked` — contract writes blocked on testnet/mainnet
- Sentry (if `SENTRY_DSN` is configured) captures unhandled exceptions tagged with `SENTRY_ENVIRONMENT` and `SENTRY_RELEASE`.
- Client-side errors are posted to the crash-reporting module (see [app/backend/src/crash-reporting](../app/backend/src/crash-reporting/README.md)) when enabled.

### How Diagnostics Help Identify Issues

| Symptom | Diagnostic to Check First |
|---|---|
| "Wrong network" warning in wallet | `/v1/network` + diagnostics panel `network` field |
| API calls hitting wrong backend | `/preview/:branchName` → verify `apiUrl` and `isFallback` |
| 403 "Preview scope required" on scoped endpoints | Confirm `x-preview-scope` header is set; check scope expiry via `PreviewScopeService.isValidScope()` |
| Page loads but all services show degraded | `/ready` — find the first failing check |
| Preview still shows old code | Diagnostics `commitShort` vs GitHub HEAD; request admin cache invalidation |
| Contract transactions blocked with `MAINNET_GATE_BLOCKED` / testnet kill-switch code | Network safety guard; see `/ready` network value and feature flags |

---

## 4. Cleanup and Expiry Expectations

### How Long Previews Remain Active

Previews are evaluated for auto-expiry by a cron job that runs **every hour (UTC)** (`CronExpression.EVERY_HOUR` in [branch-preview-auto-expiry.service.ts](../app/backend/src/branch-preview/branch-preview-auto-expiry.service.ts)).

The expiry thresholds are configurable via environment variables:

| Env Var | Default | Human Readable | Meaning |
|---|---|---|---|
| `PREVIEW_INACTIVITY_THRESHOLD_MS` | `3 * 24 * 60 * 60 * 1000` | 3 days | No activity (`lastActivityAt` or `updatedAt`) for this window → expiry reason `inactivity`. |
| `PREVIEW_MAX_AGE_MS` | `14 * 24 * 60 * 60 * 1000` | 14 days | Preview age since creation exceeds this → expiry reason `max_age`. |
| Per-preview `expiresAt` (TTL) | Set by admin on create | N/A | Hard deadline → expiry reason `ttl_expired`. |

The evaluation logic is pure and unit-tested in [branch-preview-expiry.policy.ts](../app/backend/src/branch-preview/branch-preview-expiry.policy.ts). A preview is **never** auto-expired if:
- `isActive === false` (already deactivated)
- `expiryExempt === true`
- `isShared === true` (shared team environments persist)

Preview scopes (data isolation) have their own lifecycle:
- Default TTL at creation: 7 days (`DEFAULT_PREVIEW_TTL_MS` in [preview-scope.types.ts](../app/backend/src/preview-scope/preview-scope.types.ts))
- Daily midnight cron (`CronExpression.EVERY_DAY_AT_MIDNIGHT`) sweeps expired scopes and calls `delete_expired_preview_scope_data` to purge associated rows, then deletes the scope row itself.

### What Happens When Previews Expire

1. The hourly sweep marks the preview `isActive = false` and records `autoExpiredAt` and `autoExpiryReason` (`ttl_expired`, `inactivity`, or `max_age`).
2. The branch name is evicted from the LRU cache so the next lookup returns **fallback** (`isFallback: true`) instead of stale URLs.
3. An audit row is inserted into `branch_preview_expiry_audit` and an event `branch.preview.auto_expired` is emitted on `EventEmitter2`.
4. Separately, preview-scoped data (per `preview_scopes` table) is deleted by the midnight sweep with a row-count summary logged.

### Contributor Responsibilities for Removing Unused Resources

- Close PRs that are no longer being worked on. Closing a PR is the signal to reviewers/admins that the preview can be deleted.
- For long-running work branches, verify you still need the preview every few days; if not, ask an admin to delete it.
- If you need a preview to persist longer than the TTL, ask an admin to either extend `ttlMs` or mark it `expiryExempt: true` with a justification.
- Preview-scope data is auto-purged, but avoid uploading large fixtures or PII test data; use synthetic test users and testnet-only mnemonics.

### Automated Cleanup Processes

| Process | Schedule | What It Cleans |
|---|---|---|
| `branch-preview-auto-expiry` cron | Every hour (UTC) | Deactivates branch previews matching TTL / inactivity / max-age policy. Updates expiry audit table. |
| `POST /admin/branch-previews/cleanup-expired` | Admin on-demand | Idempotent manual trigger of the same sweep as the hourly cron. Returns `{ deactivated: N }`. |
| `cleanupExpiredScopes` cron in PreviewScopeService | Every day at midnight UTC | Purges rows associated with each expired scope via Supabase RPC `delete_expired_preview_scope_data`, then drops the scope row. |
| Admin cache-clear endpoints | Admin on-demand | `POST /admin/branch-previews/:branchName/invalidate-cache` for one branch; `POST /admin/branch-previews/cache/clear` for the whole LRU. |
| Vercel auto-archival | Vercel platform policy | Older preview deployments are archived by Vercel after a platform-defined inactivity window (see Vercel docs for current policy). |

---

## 5. Testnet Safeguards

Preview environments are **testnet / development environments only**. Before testing anything that touches Stellar, read and follow these safeguards.

> ⚠️ **WARNING — READ FIRST:** Never use production wallets, production secret keys, or real (mainnet) funds in any preview environment. Previews default to testnet. Accidentally sending real funds to a preview escrow address means losing them permanently.

### Environment Safeguards Already Implemented

1. **Network bootstrap defaults to testnet.** `resolveNetworkSnapshot()` in [network.config.ts](../app/backend/src/config/network.config.ts) defaults to `testnet` when `NETWORK` / `STELLAR_NETWORK` are not set. Invalid values (anything other than `testnet` or `mainnet`) throw and abort startup. Conflicting values between the two aliases also throw.

2. **Env validation hardens the network choice.** `env.schema.ts` ([env.schema.ts](../app/backend/src/config/env.schema.ts)) uses Joi with `.valid("testnet", "mainnet").required()` on `NETWORK`, so any invalid value refuses to start.

3. **Preview deployments are wired to testnet.** The Vercel preview env profile in [VERCEL_DEPLOYMENT_GUIDE.md](../app/frontend/VERCEL_DEPLOYMENT_GUIDE.md) sets `NEXT_PUBLIC_STELLAR_NETWORK=testnet` and points the backend at `https://api-staging.quickex.to` (staging = testnet). The Runtime Config Matrix in [RUNTIME-CONFIG-MATRIX.md](./RUNTIME-CONFIG-MATRIX.md) confirms all non-production profiles use `NETWORK=testnet`.

4. **Network Safety Guard blocks contract writes on both testnet and mainnet through feature-flag kill switches.** See [network-safety.guard.ts](../app/backend/src/feature-flags/network-safety.guard.ts):
   - Routes decorated with `@RequiresFlag(TESTNET_CONTRACT_WRITES_FLAG)` re-read the flag fresh on each request (not via cache). If the flag is disabled, the request is rejected with HTTP 503 `{ code: "CONTRACT_WRITES_DISABLED", ... }` and an audit event `network_safety_gate.blocked` is recorded.
   - Routes on mainnet gated with any other flag also go through the guard; a disabled flag returns 503 with `MAINNET_GATE_BLOCKED`.
   - All block events log the path, method, network, user ID, and the reason returned by the flag evaluator.

5. **Indexer Lag Guard blocks high-risk operations when event ingestion is behind.** The `IndexerLagGuard` (with threshold from `INDEXER_LAG_THRESHOLD_LEDGERS`, default 100 ledgers) ensures the backend's view of chain state is not stale before allowing operations that depend on accurate indexing.

6. **CORS preview origin allowlisting.** Setting `CORS_VERCEL_PROJECT=quickex-frontend` auto-allows any `https://<slug>-*.vercel.app` origin, so preview frontend apps can call the staging/testnet backend without per-deployment CORS registration.

### Pre-Testing Checklist (Run Every Time)

- [ ] Diagnostics panel shows `network: testnet` (or explicitly known, approved test config).
- [ ] Wallet extension (Freighter, Albedo, etc.) is switched to **Testnet** before connecting.
- [ ] Backend `/v1/network` returns the expected network.
- [ ] `/preview/<your-branch>` returns `isFallback: false` and the correct `apiUrl`.
- [ ] All test accounts are funded from the [Stellar Testnet Friendbot](https://friendbot.stellar.org/), not from a mainnet wallet.
- [ ] Any secret keys in `.env` or used for signing start with `S...` and are known testnet-only keypairs.

### What Counts as a Safe vs. Unsafe Preview Action

| Safe (Previews) | Unsafe (Do NOT Do) |
|---|---|
| Using Friendbot-funded testnet XLM | Depositing real XLM from a mainnet account |
| Using a testnet-only secret key for signing | Pasting your personal mainnet `STELLAR_SECRET_KEY` |
| Testing with preview-scope synthetic user data | Reusing real customer / production PII test fixtures |
| Pointing integrations at `*-testnet.stellar.org` endpoints | Pointing integrations at Horizon / Soroban RPC `*.mainnet.*` URLs |
| Verifying the diagnostics panel before each session | Assuming the panel or URL "just works" without verifying |

---

## 6. Troubleshooting

### A. Mismatched Configuration

**Symptoms:**
- Wallet connects to the wrong network (mainnet instead of testnet or vice versa).
- API calls go to `api.quickex.to` (production) when you expected preview/staging.
- Contract methods return `CONTRACT_WRITES_DISABLED` or `MAINNET_GATE_BLOCKED` unexpectedly.
- CORS errors in the browser console despite the preview being from the Vercel project.

**Recovery Steps:**

1. **Verify your local / preview environment variables.**
   - Backend: Compare your runtime `/ready` `environment.details` against [.env.example](../app/backend/.env.example). Confirm `NETWORK=testnet` and that you have not accidentally set a mainnet `HORIZON_URL` / `SOROBAN_RPC_URL` override.
   - Frontend: Inspect `getDeploymentInfo()` output (diagnostics panel or browser console). Confirm `network` and `apiUrl` match the intended environment.
   - For the contract registry version, check `contractRegistryVersion` on both the frontend panel and the `GET /preview/:branchName` response; they should agree.

2. **Confirm the network bootstrap matches expectations.**
   ```bash
   curl https://<your-preview-api>/v1/network
   ```
   Verify `network`, `passphrase` (testnet = `Test SDF Network ; September 2015`, mainnet = `Public Global Stellar Network ; September 2015`), and all URLs. Default endpoints per network are defined in [network.config.ts](../app/backend/src/config/network.config.ts).

3. **Fix stale or mismatched secrets / config values.**
   - Backend env vars are validated once on startup by `AppConfigService` against the Joi schema. Changing values in a running container will not take effect; a redeploy / restart is required.
   - Vercel preview env vars are captured at build time. To change them, update the Vercel dashboard's Preview environment and trigger a redeploy by pushing a commit or using the Vercel UI.
   - Fallback URLs for unknown branches come from `FALLBACK_API_URL` / `FALLBACK_FRONTEND_URL`. If these resolve to wrong endpoints, an admin needs to update the env and redeploy the backend.

4. **Verify CORS for Vercel previews.**
   - Confirm `CORS_VERCEL_PROJECT` is set to the correct slug (e.g. `quickex-frontend`) so the pattern `https://<slug>-*.vercel.app` matches your preview URL's origin.
   - If the preview is on a non-Vercel host, add the origin to `CORS_ALLOWED_ORIGINS` (comma-separated) and redeploy.

5. **If you see `NETWORK and STELLAR_NETWORK are both set but conflict`,** remove one of the two aliases from the environment and restart; they must match when both are present.

### B. Stale Preview Environment

**Symptoms:**
- Diagnostics panel shows a `commitShort` that does not match the latest commit on your PR branch.
- Changes you just pushed are not visible in the preview.
- `/preview/:branchName` returns `isFallback: true` even though you believe the preview is registered.
- Deployment logs show success but the UI shows a previous version of the page.

**Recovery Steps:**

1. **Confirm the preview is registered and active.**
   ```bash
   curl https://<backend>/preview/<your-branch-name>
   ```
   - If `isFallback: true`, ask an admin to create or re-activate the mapping via `POST /admin/branch-previews`.
   - If the preview is active but shows old `apiUrl` / `frontendUrl`, ask an admin to `PUT /admin/branch-previews/:id` with the corrected URLs and optionally a fresh `ttlMs`. Updates automatically invalidate the cache entry for that branch.

2. **Clear the branch preview cache.**
   - Admin: `POST /admin/branch-previews/<branchName>/invalidate-cache` forces the next lookup to hit the database instead of the LRU cache.
   - Admin (if widespread stale reads): `POST /admin/branch-previews/cache/clear` purges all 1000 LRU entries. Cache default TTL is 7 days; fallback mapping (unknown branches) is cached for 15 minutes ([branch-preview.cache.ts](../app/backend/src/branch-preview/branch-preview.cache.ts)).

3. **Force a rebuild / redeploy.**
   - Frontend (Vercel): Push an empty commit or go to the Vercel dashboard → Deployments → select the latest → "Redeploy".
   - Backend: Re-run the deploy workflow (or admin calls the deploy hook). The [deploy-app action](../.github/actions/deploy-app/action.yml) waits up to 4 minutes for `/health` to return 200 before failing the step.
   - If the deployment was "successful" but `/ready` is returning `ready: false`, inspect each check name in the response and fix the dependency (Supabase connection, Horizon reachability, Soroban RPC, migrations, queue).

4. **Bust CDN / browser cache for the frontend.**
   - Vercel generally busts caches on deploy, but you can force a hard refresh (`Ctrl+Shift+R` / `Cmd+Shift+R`) or append a query string to the URL.
   - Confirm `deployedAt` in diagnostics matches your latest build time; if not, the wrong build is being served.

5. **Check preview expiry status.**
   - If the preview was auto-expired, `GET /preview` returns fallback. Ask an admin to re-create the mapping or to list previews with `GET /admin/branch-previews?includeInactive=true` and reactivate with `isActive: true` + new TTL. Expiry audit rows are written to `branch_preview_expiry_audit` with `expiry_reason` and `note`.

### C. Missing Services or Dependencies

**Symptoms:**
- Page renders but "Service Unavailable" / 503 on transaction or contract-write endpoints.
- `/ready` returns `ready: false` with one or more checks in status `down`.
- All API calls return 5xx or CORS failures; even `/health` is unreachable.
- Preview-scope-gated endpoints return 403 with "Preview scope is invalid or expired".

**Recovery Steps:**

1. **Start with the shallow then deep health probes.**
   ```bash
   # Liveness — should return 200 in <500ms
   curl -i https://<api>/health

   # Readiness — walks every dependency
   curl -i https://<api>/ready
   ```
   Map the failing check to its source in [health.service.ts](../app/backend/src/health/health.service.ts):

   | Failing Check | Where to Look |
   |---|---|
   | `supabase` down | `SUPABASE_URL` / `SUPABASE_ANON_KEY` env; confirm Supabase project is healthy. The health check runs `supabase.checkHealth()` with a 3s timeout. |
   | `migrations` down | Database schema missing; run `pnpm turbo run db:migrate` (see the migration step in [cd.yml](../.github/workflows/cd.yml)). For preview scopes, confirm `preview_scopes` table and the `delete_expired_preview_scope_data` RPC exist. |
   | `queue` down | Jobs table unreachable or empty. |
   | `horizon` down | `HORIZON_URL` wrong or network egress blocked. Default testnet: `https://horizon-testnet.stellar.org`. Preview must have outbound HTTPS. |
   | `soroban_rpc` down | `SOROBAN_RPC_URL` or `SOROBAN_RPC_URLS` (failover list) misconfigured. Default testnet: `https://soroban-testnet.stellar.org`. The check calls `getNetworkPassphrase()` via `SorobanRpcService`. |
   | `ingestion` down | Contract-event cursors inaccessible or lag too high. See `INDEXER_LAG_THRESHOLD_LEDGERS` (default 100) and `IndexerLagGuard`. |
   | `environment` down | Missing required env vars or invalid signing config. Read the `details` array for the precise missing value. |

2. **Check logs and status information in the right place.**
   - Backend: Application logs (stdout / Sentry if configured), audit events, the `environment.details` from `/ready`.
   - Frontend: Vercel deployment logs (Build, Runtime, Edge Functions), browser devtools Console + Network, crash-reporting module endpoints.
   - Contract-level: Stellar Expert explorer (testnet/public) for the contract ID returned by `GET /contracts/registry`.
   - Branch preview lifecycle: search audit logs for the branch name with the event names listed in section 3.

3. **Resolve preview scope issues.**
   - If `PreviewScopeGuard` rejects with "Preview scope is required", the caller is not sending the `x-preview-scope` header. Pass a valid scope ID obtained when the scope was created.
   - If the error is "Preview scope is invalid or expired", either recreate the scope with a fresh TTL or call `PreviewScopeService.extendScope(scopeId, ttlMs)` to extend.
   - To verify whether a scope exists and when it expires, call `PreviewScopeService.getScope(scopeId)` and compare `expires_at` to `now`.

4. **Confirm correct local vs. preview setup.**
   - Local backend: default port 4000, default network `testnet`, default Supabase at `127.0.0.1:54321` (see [.env.example](../app/backend/.env.example)).
   - Local frontend: `NEXT_PUBLIC_QUICKEX_API_URL=http://localhost:4000` in `.env.local`, diagnostics panel will show `vercelEnv: null` (null counts as not-production so the panel is visible).
   - Shared preview: API URL is typically `https://preview-api.quickex.to` or staging `https://staging-api.quickex.to` (see the environment matrix in [RUNTIME-CONFIG-MATRIX.md](./RUNTIME-CONFIG-MATRIX.md)).
   - Mobile preview builds: set `EXPO_PUBLIC_API_URL` to the preview backend, or use the staging profile; ensure the environment picker in the app (if visible) shows the expected target.

5. **Escalation path for unrecoverable issues.**
   - Document which `/ready` checks are failing, the output of `/v1/network`, the preview branch + mapping response, and the commit SHAs from both diagnostics panels.
   - Share the deployment IDs (Vercel deployment page, backend release metadata) with an admin so they can invalidate caches, re-create the branch mapping, or re-deploy a fresh environment.
   - For contract-write blocks with code `CONTRACT_WRITES_DISABLED` on testnet, check whether the testnet kill-switch flag is enabled; the flag name is `TESTNET_CONTRACT_WRITES_FLAG` (see [network-safety.guard.ts](../app/backend/src/feature-flags/network-safety.guard.ts)).

---

## Additional Resources

- [CONTRIBUTING.md](../CONTRIBUTING.md) — branch naming, PR guidelines, dev container setup.
- [RUNTIME-CONFIG-MATRIX.md](./RUNTIME-CONFIG-MATRIX.md) — per-environment API URLs, network settings, config drift risks, and runtime config tracing commands.
- [VERCEL_DEPLOYMENT_GUIDE.md](../app/frontend/VERCEL_DEPLOYMENT_GUIDE.md) — frontend Vercel previews, production deployment profile, and rollback steps.
- [env.schema.ts](../app/backend/src/config/env.schema.ts) — authoritative schema and defaults for every backend environment variable including preview fallback and expiry thresholds.
- [branch-preview.service.ts](../app/backend/src/branch-preview/branch-preview.service.ts) — backend preview lookup, admin CRUD, cache invalidation, and sweep entry points.
- [preview-scope.service.ts](../app/backend/src/preview-scope/preview-scope.service.ts) — preview scope creation, validation, extension, and midnight data cleanup.
- [deployment-info.ts](../app/frontend/src/lib/deployment-info.ts) — frontend deployment metadata source and the diagnostics panel visibility rule.
