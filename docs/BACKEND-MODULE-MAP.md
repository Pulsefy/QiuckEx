# Backend Module Ownership and Boundary Map

`app/backend/src/` holds **50 top-level directories** accumulated across many waves. This document is the answer to three questions a contributor asks before writing backend code:

1. **Who already owns this?** — one paragraph per module saying what it is responsible for.
2. **May I import it from here?** — the allowed dependency directions, and which modules are shared infrastructure that anyone may depend on.
3. **Does my change belong in an existing module or a new one?** — a decision procedure, not a vibe.

It also flags the modules that are **thin, unwired, or duplicated**, so you do not build on something that is not actually serving traffic.

Companion documents:

- [CAPABILITY-MAP.md](./CAPABILITY-MAP.md) — whether a flow is Live / Partial / Mocked / Experimental. Read it for *maturity*; read this one for *ownership*.
- [BACKEND-CLIENT-CONTRACT-MAP.md](./BACKEND-CLIENT-CONTRACT-MAP.md) — endpoint-level wiring between clients and the backend.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — the cross-surface picture (frontend / backend / contracts).
- [TESTNET-INCIDENT-RUNBOOK.md](./TESTNET-INCIDENT-RUNBOOK.md) — which of the operational modules to reach for during an incident.

> **Scope note.** This document describes the tree as it exists today, including its inconsistencies. Where the current state violates the rules stated here, the violation is called out explicitly rather than quietly idealised away. Those call-outs are the backlog.

---

## 1. Layers

Every module sits in exactly one layer. The layer determines who may import it.

| Layer | Meaning | Modules |
|---|---|---|
| **L0 — Platform** | Framework-level concerns with no domain knowledge. Imported by anything. | `config`, `common`, `types`, `tracing`, `sentry`, `metrics`, `supabase` |
| **L1 — Cross-cutting services** | Domain-agnostic capabilities every feature needs: identity, audit trail, gating, async work, eventing. Imported by any L2/L3 module. | `auth`, `api-keys`, `audit`, `feature-flags`, `job-queue`, `events`, `dto` |
| **L2 — Chain access** | The only modules permitted to talk to Horizon, Soroban RPC, or read the on-chain event stream. | `stellar`, `transactions`, `ingestion`, `contracts` |
| **L3 — Product domains** | Business features. May depend on L0–L2 and, sparingly, on named peers. | `links`, `usernames`, `payments`, `marketplace`, `refunds`, `receipts`, `fiat-ramps`, `notifications`, `analytics`, `dashboard-feed`, `transaction-timeline`, `scam-alerts`, `abuse-signals`, `asset-metadata`, `privacy`, `exports`, `reconciliation`, `developer` |
| **L4 — Operations & environment** | Admin, diagnostics, release, and preview surfaces. May read from everything below; **nothing below may import them**. | `health`, `operations`, `indexer-lag`, `support-bundle`, `rc-validation`, `environment-parity`, `branch-preview`, `deployment-sync`, `preview-scope`, `runtime-config`, `soroban-tooling`, `manifests`, `crash-reporting`, `demos` |

### The rule

> **Imports point downward.** A module may import from its own layer or any layer below it. It may never import from a layer above.

Two consequences worth stating plainly:

- **L0 must not import L1–L4.** Platform code that knows about a product domain is no longer platform code.
- **L4 is a sink.** `operations`, `support-bundle`, and `rc-validation` deliberately reach across many domains to assemble a diagnostic view. That is their job. It is also why nothing may depend on them — doing so would turn a read-only aggregate into a load-bearing dependency.

### Known violations of the layering rule

These are real, present in the tree today, and should be fixed rather than imitated:

| Violation | Where | Why it is wrong |
|---|---|---|
| `supabase` (L0) imports reconciliation types | [supabase.service.ts:11](../app/backend/src/supabase/supabase.service.ts#L11) imports from `../reconciliation/types/reconciliation.types` | The database client should not know a product domain exists. Move the shared row shapes down into `supabase` or up into a neutral type module. |
| `dto` (L1) imports `links` (L3) | [payment-link-status.dto.ts:2](../app/backend/src/dto/link/payment-link-status.dto.ts#L2) imports `LinkState` from `../../links/link-state-machine` | The shared DTO barrel now transitively drags in a product domain. `LinkState` is a contract shape and belongs in `dto`, with `links` importing it. |
| Two `HorizonService` classes | [stellar/horizon.service.ts](../app/backend/src/stellar/horizon.service.ts) (88 lines) and [transactions/horizon.service.ts](../app/backend/src/transactions/horizon.service.ts) (291 lines) | Same class name, different capabilities, split consumer base. `asset-metadata`, `health`, and `soroban-tooling` use the `stellar` one; `links`, `payments`, `scam-alerts`, and `transaction-timeline` use the `transactions` one. Neither is a superset. This is the single largest source of "I could not find the existing owner" in the backend. |
| Route-prefix collision on `links` | [links.controller.ts](../app/backend/src/links/links.controller.ts) and [scam-alerts.controller.ts](../app/backend/src/scam-alerts/scam-alerts.controller.ts) both declare `@Controller("links")` | Two modules serve sibling paths under one prefix. Route ownership is not discoverable from the URL. |

---

## 2. Module ownership

Each entry states what the module owns, its layer, its externally served route prefix (if any), and its status. Status values:

- **Active** — wired into [app.module.ts](../app/backend/src/app.module.ts) and serving.
- **Conditional** — registered only under certain environment conditions.
- **Unwired** — code exists, module is **not imported anywhere**; its controllers serve no traffic.
- **Library** — intentionally has no Nest module, or is imported directly rather than registered globally.

### L0 — Platform

**`config`** — *Active. Library + `v1/network`.* Owns environment ingestion end to end: the Joi schema in [env.schema.ts](../app/backend/src/config/env.schema.ts) that validates every variable at boot, the typed accessor surface `AppConfigService`, and the derived config objects for CORS, rate-limit profiles, Stellar network selection, and SEP-24. Any question of the form "what is the current network / threshold / URL" is answered here, never by reading `process.env` at the point of use. It also serves `GET /v1/network` so clients can discover the network the backend is actually running against. It is the one module with zero backend dependencies.

**`common`** — *Active. Library.* Owns request-lifecycle machinery shared by every route: the correlation-ID and organization-context middleware, the global HTTP exception filter and its error catalog, the idempotency store and interceptor, cursor pagination helpers, Winston logging config, redaction utilities, and the Soroban error-code mapper that turns raw contract errors into stable client-facing codes. If a behaviour must apply uniformly to all requests, it belongs here. `IdempotencyModule` lives under `common/idempotency` and is imported directly by `transactions` and `fiat-ramps` rather than registered globally.

**`types`** — *Active. Library.* Owns ambient TypeScript declarations only — the augmented `Express.Request` carrying `apiKey`, `organizationContext`, and `previewScope`, plus shims for untyped dependencies. It contains no runtime code. When a guard or middleware attaches something to the request, its shape is declared here so every downstream handler sees it.

**`tracing`** — *Active. Library.* Owns OpenTelemetry setup and the primitives that carry trace context: the OTel config, the `withSpan` helper, correlation baggage propagation, and `createTracedFetch`, which is how outbound HTTP (Horizon, Soroban RPC, Supabase, webhooks) gets spans without each caller instrumenting itself. It is a library rather than a Nest module because tracing must initialise before the Nest container.

**`sentry`** — *Active.* Owns error reporting to Sentry: the instrumentation bootstrap that must run before anything else in [main.ts](../app/backend/src/main.ts), the exception filter that forwards unhandled errors, and the service wrapper used for explicit captures. It is first in the app module's import list for that reason.

**`metrics`** — *Active. `metrics`.* Owns the Prometheus registry and every metric the backend exposes, plus the middleware and global interceptor that record HTTP volume, latency, active connections, and rate-limit rejections without per-route wiring. Domain modules record their own gauges and counters through `MetricsService` — they never construct a `prom-client` object themselves, which is what keeps metric names centrally reviewable. The `/metrics` endpoint is guarded separately from the rest of the API.

**`supabase`** — *Active. Library.* Owns the single Supabase client instance, its traced `fetch`, and the error-normalisation layer that maps Postgres/PostgREST failures into typed application errors. Every module that reads or writes persistent state goes through `SupabaseService`; there is no second database client in the tree. *Boundary caveat:* it currently imports reconciliation types (see §1), which it should not.

### L1 — Cross-cutting services

**`auth`** — *Active. Library.* Owns request authorisation primitives with no routes of its own: `ApiKeyGuard` (validates `X-API-Key` and populates `req.apiKey`), `OrganizationRoleGuard` and `CustomThrottlerGuard` (both registered globally in the app module), and the decorators that configure them — `@RequireScopes`, `@RequireOrgRole`, `@RateLimitGroupTag`. `AuthModule` itself is not registered in `app.module.ts`; it is imported by the modules that need the guards (`job-queue`, `privacy`). Anything that decides *whether a caller may act* belongs here.

**`api-keys`** — *Active. `api-keys`.* Owns the lifecycle of programmatic credentials: creation with bcrypt hashing and prefix-based lookup, scope assignment, per-key quota and rate limits, rotation, revocation, and usage counting. It is the store `auth`'s `ApiKeyGuard` reads from. The split is deliberate — `api-keys` owns the *record*, `auth` owns the *decision*.

**`audit`** — *Active. `admin/audit`.* Owns the append-only record of privileged actions: `AuditService.log(actor, action, target, metadata, requestId)` plus an interceptor for automatic capture and a query endpoint for admin review. Sixteen modules write to it, which makes it the de facto forensic timeline during an incident. *Caveat:* the service also keeps an in-memory `logs` array alongside the Supabase write; treat the database as authoritative.

**`feature-flags`** — *Active. `admin/feature-flags`, `feature-flags`.* Owns runtime gating: flag CRUD, cached evaluation, an uncached `evaluateFlagFresh` path, the `@RequiresFlag` decorator, and `NetworkSafetyGuard`. It also owns the **contract-write kill switch** — the `testnet.contract_writes` flag, which the guard reads *fresh on every request* so a flip propagates across instances without waiting for cache expiry, and audits every block. Any "turn this off in production without a deploy" requirement belongs here rather than in a new environment variable.

**`job-queue`** — *Active. `admin/jobs`.* Owns all asynchronous and retried work: the job repository and executor, the registry mapping `JobType` to handlers, exponential-backoff retry with cancellation tokens, the dead-letter monitor that alerts on DLQ depth and oldest-job age, replay bookkeeping, queue metrics, and the admin surface for listing, cancelling, retrying, bulk-retrying, and inspecting the DLQ. Handlers for the six job types (`webhook_delivery`, `recurring_payment`, `export_generation`, `reconciliation`, `stellar_reconnect`, `sep24_status_poll`) live *inside* this module and call into their owning domain. That inversion is intentional: the queue owns scheduling and retry semantics, the domain owns the work. It is the widest-reaching L1 module by import count.

**`events`** — *Active. Library.* Owns the transactional outbox: `OutboxService.stage()` is called inside the same database transaction as the originating state change, and `OutboxDispatcher` publishes durably afterwards, with depth and dispatch-lag metrics. It also owns the typed cross-module event contracts (`contract-registry.events.ts`, `notification.events.ts`) used with the Nest `EventEmitter`. Use the outbox when a state change and its side effect must not diverge; use the emitter for best-effort in-process fan-out.

**`dto`** — *Active. Library.* Owns request/response shapes shared by more than one module — link, transaction, username, and pagination DTOs — so that two controllers describing the same concept cannot drift. Module-local DTOs stay in the owning module's `dto/` folder; a shape is promoted here only when a second module needs it. *Caveat:* it currently imports `LinkState` from `links` (see §1), inverting the intended direction.

### L2 — Chain access

**`stellar`** — *Active. `stellar`.* Owns classic-Stellar read paths that serve the link generator: the verified-asset list, strict-receive and strict-send path previews, quote issuance and retrieval, Soroban preflight simulation (flag-gated behind `testnet.contract_writes` + `NetworkSafetyGuard`), and the recurring-payment processor. It carries the smaller of the two `HorizonService` implementations, used by `asset-metadata`, `health`, and `soroban-tooling`.

**`transactions`** — *Active. `transactions`.* Owns transaction composition and submission: listing transactions for an address, `compose` (with `build` as a backward-compatible alias), `simulate`, and `submit`, plus `SorobanRpcService` — which owns RPC endpoint selection, timeout and retry policy, and multi-endpoint failover with `soroban_rpc_failover_total` / `soroban_rpc_active_endpoint` metrics. It carries the larger `HorizonService`, used by `links`, `payments`, `scam-alerts`, and `transaction-timeline`. It also owns the simulation-error mapper and XDR param builders. **All Soroban RPC traffic goes through this module.**

**`ingestion`** — *Active. `indexer`.* Owns the read side of the chain: polling Horizon and Soroban RPC for contract events, parsing them against versioned schemas, deriving stable event IDs, persisting them into the typed event repositories (escrow, stealth, privacy, admin), maintaining per-contract indexer checkpoints and cursors, and quarantining anything it cannot parse into `unparsed_soroban_events`. It also owns Horizon endpoint failover and the admin routes for reindexing and replaying unparsed events. Anything downstream that needs "what happened on chain" reads the tables this module fills — it does not poll the network itself.

**`contracts`** — *Active. `contracts`, `v1/contracts/views`.* Owns the contract registry: which contract IDs and WASM hashes are active per environment, publish and rollback of registry entries, deployment artifacts, contract specs and derived read-only views, the method allowlist guard, and change webhooks that notify subscribers when the registry moves. Clients resolve contract addresses through this module rather than embedding them, which is what makes registry rollback a viable incident mitigation.

### L3 — Product domains

**`links`** — *Active. `links`, `payment-links`, `links/bulk`, `links/recurring`.* The largest domain module. Owns the payment link end to end: creation and metadata, the `DRAFT → ACTIVE → EXPIRED|PAID → REFUNDED` state machine, public status lookup used by the pay page, expiry sweeping, bulk/CSV generation, and the recurring-payment schedule with its repository and scheduler. Its link constraints and error catalog are the canonical definition of what a valid link is.

**`usernames`** — *Active. `username`.* Owns the username namespace and public profile: reservation and creation, validation rules, public/private toggling, profile lookup by name, and the **discovery surface** — `search`, `trending`, `recently-active`, and `featured`, backed by a discovery cache. This module is the sole owner of user-facing discovery on the backend. If you are about to write a "find users" query anywhere else, it belongs here. (The frontend discovery page still renders local mock data instead of calling these endpoints — see [CAPABILITY-MAP.md](./CAPABILITY-MAP.md).)

**`payments`** — *Active. `payments`.* Owns the recent-payments read for an address: a thin controller and service over `HorizonService.getPayments` with `since`/`limit` filtering. **Intentionally thin** — roughly forty lines of logic. It is *not* a general payments domain; nothing about link state, refunds, or reconciliation lives here despite the name. Treat it as a Horizon convenience read, and do not expand it without deciding whether the code actually belongs in `links` or `transactions`.

**`marketplace`** — *Active. `marketplace`.* Owns username listings and bidding: creating and cancelling listings, listing queries with sorting and bid aggregation, listing detail with derived state hints, placing bids, and accepting a bid. Its error catalog defines the marketplace's rejection reasons. Backend routes are real; several client-side marketplace flows are still mocked.

**`refunds`** — *Active. `admin/refunds`.* Owns refund eligibility and initiation: the eligibility rules for payments and escrows, reason codes, and the admin-initiated refund path, gated by feature flags and written to the audit log. Eligibility logic lives in `refunds.eligibility.ts` and is the single place that decides whether something is refundable.

**`receipts`** — *Unwired. Would serve `v1/receipts`.* Owns the normalised payment receipt: it orchestrates Horizon, Soroban RPC, and indexer metadata, then normalises them into a stable receipt schema with a content hash for tamper evidence. **`ReceiptsModule` is not imported anywhere**, so `/v1/receipts` is not served. The normaliser and schema are complete; only the wiring is missing.

**`fiat-ramps`** — *Active. `fiat-ramps`.* Owns the SEP-24 deposit/withdraw integration: anchor discovery via the SEP-1 TOML, SEP-10 authentication, interactive SEP-24 initiation, the transaction repository, and status polling — both the in-process poller and the `sep24_status_poll` job handler. It uses `IdempotencyModule` so a retried initiation does not open two anchor sessions.

**`notifications`** — *Conditional (skipped on local Supabase). `notifications`, `notifications/preferences`, `webhooks`, `telegram`, `admin/notification-templates`.* The largest module in the tree by file count, and the one most often mistaken for several modules. It owns **all outbound user-facing messaging**: outbound webhook subscriptions with HMAC signing, secret regeneration, delivery logs, per-attempt inspection, manual redelivery, and replay limiting; in-app notifications with read/unread state; per-user notification preferences and their evaluator; a versioned notification-template system; rate limiting; the Telegram bot provider; and the pluggable `NotificationProvider` interface. Actual delivery is executed by the `webhook_delivery` job handler in `job-queue`.

**`analytics`** — *Active. `analytics`.* Owns aggregate reporting for the dashboard: payment volume, conversion, per-asset breakdowns, and interval bucketing, computed through Supabase RPCs, plus the export of those reports. It reads persisted data only — it has no backend module dependencies at all. Distinct from `metrics`, which is operational telemetry about the service; `analytics` is product data about payments.

**`dashboard-feed`** — *Active. `dashboard-feed`.* Owns the cursor-paginated cross-source activity feed for an address, fetching each source independently so one failing source degrades rather than empties the feed. Overlaps conceptually with `transaction-timeline`; the split is **feed = many entities for one address**, **timeline = one entity's history**.

**`transaction-timeline`** — *Active. `transaction-timeline`.* Owns the per-transaction chronology: the ordered payment, refund, and webhook events for a single transaction, assembled from the repository plus Horizon. Use it when the question is "what happened to *this* payment"; use `dashboard-feed` when it is "what happened to *this account*".

**`scam-alerts`** — *Active. `links` (shared prefix).* Owns pre-payment risk scanning of a link or destination: memo requirements per asset, whitelists and blocklists, high-value and unreasonable-amount thresholds, suspicious memo patterns, account-age and frequency heuristics, and external blocklist sources — returning a typed severity and alert type. It scans *content* a user is about to pay. *Caveat:* it shares the `links` route prefix with the `links` module (see §1).

**`abuse-signals`** — *Active. `admin/abuse-signals`.* Owns behavioural abuse scoring at the request layer: middleware applied to the `payment-links` and `links` routes records signals, aggregates them by IP and actor with weighted scoring, exposes an admin review surface, and emits `abuse_signal_score` and outcome counters. The distinction from `scam-alerts` is **who is acting** (`abuse-signals`) versus **what is being paid** (`scam-alerts`).

**`asset-metadata`** — *Active. `assets`.* Owns display metadata for Stellar assets: issuer TOML fetching with caching, branding and fallbacks (including native XLM), the verified-asset overlay, and admin asset routes. Any question of "what icon, name, or verification badge does this asset have" is answered here.

**`privacy`** — *Active. `privacy`, `admin/privacy`.* Owns two related things: the **stealth-address cryptography** (ECDH envelopes, ephemeral keypairs, encryption and decryption of stealth payment metadata) and the **data-retention policy** — the scheduler that purges expired personal data on the configured schedule, with admin visibility into what was purged.

**`exports`** — *Active. `exports`.* Owns user-requested data exports: accepting an export request, queueing it as an `export_generation` job, storing the artifact via `ExportStorageModule`, issuing signed download links, and retiring artifacts on the retention schedule. It owns the *request and delivery*; generation runs in `job-queue`.

**`reconciliation`** — *Conditional (skipped on local Supabase). `reconciliation`.* Owns the ledger-versus-database truth check: scheduled and manually triggered runs, per-run reports with drift classification against configurable count and amount thresholds, alerting on drift and on consecutive failures, historical backfill, auto-matching of unmatched records, and the unmatched queue with resolve and dismiss actions. It is the authority on whether recorded state matches chain state, and its `reconciliation_drift_active` and `reconciliation_consecutive_failures` gauges are primary incident signals.

**`developer`** — *Conditional (skipped on local Supabase). `developer`.* Owns the self-service developer surface: bulk API-key revocation, sample webhook event generation, webhook endpoint testing with a bounded timeout, an integration-health summary, and a ping. It is a convenience layer over `api-keys` and `notifications` — it should not accumulate its own persistent state.

### L4 — Operations & environment

**`health`** — *Active. `health`, `ready`, `status`.* Owns liveness, readiness, and public status. `/health` is shallow; `/ready` performs per-dependency checks with individual timeouts across Supabase, Horizon, and Soroban RPC and returns 503 when a critical dependency has hard-failed; `/status` is a throttled, ETag-cached, non-sensitive summary suitable for a public status page. Probe configuration belongs here, not in the individual dependencies.

**`operations`** — *Active. `admin/operations`.* Owns the consolidated operator dashboard: indexer status, ingestion lag, webhook delivery backlog, and recent errors with actor redaction. It computes nothing itself — it reads `indexer-lag`, `notifications`, and `audit` and presents them together. This is the intended first stop during an incident.

**`indexer-lag`** — *Active. Library.* Owns the lag measurement and the guard built on it: a one-minute cron comparing the network's latest ledger against the last indexed checkpoint, the `indexer_lag_ledgers` and `indexer_lag_guard_status` metrics, and `IndexerLagGuard` with `@RequiresIndexerLagCheck`, which rejects lag-sensitive routes when the indexer falls behind `INDEXER_LAG_THRESHOLD_LEDGERS`. `INDEXER_LAG_GUARD_ENABLED` and `INDEXER_LAG_GUARD_OVERRIDE` control enforcement.

**`support-bundle`** — *Active. `admin/support/bundle`, `support/bundle-references`.* Owns the sanitised diagnostic export: a single admin-scoped JSON bundle of network config, contract registry state, indexer status and checkpoints, and recent errors, with secrets and PII redacted and request-ID inclusion opt-in. The reference sub-surface lets a bundle be cited from an issue without re-exporting it. This is the artifact to attach to a bug report or incident record.

**`rc-validation`** — *Active. `admin/rc-validation`.* Owns the release-candidate gate: it aggregates smoke and readiness probes, contract-registry completeness, indexer lag, and environment parity into classified blockers with an overall `releaseReady` flag. `GET /admin/rc-validation/report` is step 0 of the [release readiness checklist](../RELEASE_READINESS_CHECKLIST.md).

**`environment-parity`** — *Active. `api/environment-parity`.* Owns detection of configuration drift between environments — endpoints, versions, and feature flags — plus staging seed data and the shadow-traffic middleware that mirrors production-shaped requests at staging. Records `environment_parity_check_results` and `shadow_traffic_requests_total`.

**`branch-preview`** — *Active.* Owns per-branch preview environment records: registration, cached lookup of a branch's API and frontend URLs, network and contract version, and the auto-expiry policy that reclaims stale previews. Falls back to configured defaults when a branch has no registration.

**`deployment-sync`** — *Active.* Owns ingestion of GitHub deployment status: signature-verified webhooks, mapping GitHub deployment states onto internal branch-deployment records, and exposing the current deployment for a branch. It is how the backend learns that a preview or environment moved without polling GitHub.

**`preview-scope`** — *Active. Library.* Owns data isolation for previews: middleware reading `X-Preview-Scope`, a service backed by the `preview_scopes` table, and a guard plus decorator that confine scoped requests to their own data. Any feature that must not leak preview data into shared tables depends on this.

**`runtime-config`** — *Active. `v1/runtime-config`.* Owns the single client-facing bootstrap document: network config, resolved contract entries, feature-flag snapshot, preview metadata, and the mobile minimum-version policy. Clients fetch one document here instead of assembling config from four endpoints. See [RUNTIME-CONFIG-MATRIX.md](./RUNTIME-CONFIG-MATRIX.md).

**`soroban-tooling`** — *Active. `developer/testnet`.* Owns testnet developer conveniences: contract deployment helpers and friendbot-style account funding. Testnet-only by construction — nothing here should ever be reachable on mainnet.

**`manifests`** — *Unwired. Would serve `manifests`.* Owns structural diffing of environment manifests — contracts, URLs, and feature flags — producing a per-key `added | removed | modified | unchanged` diff. **`ManifestsModule` is not imported anywhere.** The diff algorithm is pure and self-contained; only the wiring is missing.

**`crash-reporting`** — *Unwired. Would serve `crash-reporting`.* Owns opt-in client crash and log capture: a crash-capture filter, a bounded rolling log buffer, strict redaction of secrets and PII, issue submission, and per-user settings. **`CrashReportingModule` is not imported anywhere**, and the feature is disabled by default even when wired.

**`demos`** — *Unwired. Would serve `v1/demo`, `seed-reset`.* Owns demo fixtures and the seed-reset lifecycle: seeding and clearing demo links and transactions, a scheduled reset, and status endpoints. **`DemoModule` is not imported anywhere**, so despite complete controllers, guards, and a scheduler, **seed reset is not currently served**. This matters operationally — see the [incident runbook](./TESTNET-INCIDENT-RUNBOOK.md).

---

## 3. Shared infrastructure

Five modules are **shared infrastructure**: any module may depend on them, they may not depend on any product domain, and changing them affects everything.

| Module | Contract with callers |
|---|---|
| `config` | Read configuration through `AppConfigService`. Never read `process.env` at a call site. Adding a variable means adding it to [env.schema.ts](../app/backend/src/config/env.schema.ts), the typed interface, `.env.example`, and an accessor. |
| `supabase` | All persistence goes through `SupabaseService`. Do not create a second client. Repositories live in the owning domain, not here. |
| `metrics` | Register metrics through `MetricsService` so names stay centrally reviewable. Adding one requires updating the registered-metric count assertion in the metrics tests. |
| `common` | Behaviour that must apply to every request — middleware, filters, interceptors, idempotency, pagination, redaction. Domain logic never lands here. |
| `tracing` | Outbound HTTP uses `createTracedFetch` or `withSpan`. Do not call bare `fetch` for an external dependency. |

Three L1 modules are near-infrastructure — widely depended on, but they carry domain opinions and are not free to import:

- **`auth` / `api-keys`** — every guarded route depends on them. Changing scope semantics is a breaking change across the API.
- **`audit`** — write to it from any privileged action. Sixteen modules already do.
- **`job-queue`** — adding a `JobType` means adding a handler here, and the handler calls into your domain rather than your domain owning the retry loop.

---

## 4. Deciding where new code goes

Work through this in order. Stop at the first rule that fires.

**1. Does an existing module already own this concept?**
Search by concept, not by filename — the owner is often named for the domain, not the operation. The highest-yield checks, given the duplication in this tree:

- Discovery, search, trending, featured, profile lookup → **`usernames`**. There is no other discovery owner.
- Anything reading Horizon → one of the two `HorizonService`s. Extend the one your module's peers already use; do not add a third.
- Anything calling Soroban RPC → **`transactions`** (`SorobanRpcService`).
- Anything reading on-chain history → **`ingestion`** tables. Do not poll the chain from a domain module.
- Outbound webhooks, in-app messages, templates, Telegram → **`notifications`**. All of it.
- Retries, backoff, scheduled work → **`job-queue`**, as a handler.
- Admin read-only aggregation → **`operations`** or **`support-bundle`**, not a new admin module.

If an owner exists, **extend it**, even if that means the module grows.

**2. Is it request-lifecycle behaviour that applies to every route?**
→ `common` (middleware, filter, interceptor) or `auth` (a guard). Not a new module.

**3. Is it a read-only diagnostic view assembled from other modules?**
→ `operations` or `support-bundle`. A new L4 module is justified only when it owns state or a schedule of its own — `indexer-lag` and `environment-parity` qualify; a new endpoint that joins three existing services does not.

**4. Is it a distinct product domain with its own persistent state, lifecycle, and vocabulary?**
→ A new L3 module. All four must hold:

- It owns at least one table no other module writes.
- It has a lifecycle a state machine could describe, or an external integration boundary.
- Its nouns do not already appear in another module's public surface.
- You can state its ownership paragraph in this document without the word "and" joining two unrelated responsibilities.

**5. Otherwise, it is a feature of an existing module.** Put it there.

### Creating a module

1. Give it a directory named for the **domain**, not the operation — `refunds`, not `refund-processor`.
2. Declare its layer, and check every import points downward.
3. Standard shape: `<name>.module.ts`, `<name>.controller.ts`, `<name>.service.ts`, `<name>.repository.ts` (Supabase access), `dto/`, `types/`, and errors in `errors/` when the domain has rejection reasons worth naming.
4. **Register it in [app.module.ts](../app/backend/src/app.module.ts).** Four modules in this tree skipped this step and serve nothing. If registration is conditional, say so in the ownership paragraph.
5. Choose a route prefix nobody else uses. Two modules already collide on `links`.
6. Add its ownership paragraph to §2 of this document, and a row to [CAPABILITY-MAP.md](./CAPABILITY-MAP.md) with its maturity.

### Extending a module

- Cross-module reads go through the owner's **service**, never its repository. Repositories are module-private.
- Needing a peer's repository means either the boundary is wrong or the shape belongs in `dto`.
- Sharing a type with exactly one other module: export it from your service's module. With three or more: promote it to `dto`.
- Adding an environment variable: schema, typed interface, `.env.example`, accessor. All four.

---

## 5. Status summary

Modules that are **not fully wired** — do not build on these without wiring them first:

| Module | Status | Consequence |
|---|---|---|
| `receipts` | Unwired — `ReceiptsModule` imported nowhere | `/v1/receipts` is not served. Normaliser and schema are complete. |
| `manifests` | Unwired — `ManifestsModule` imported nowhere | `/manifests` is not served. The diff algorithm is pure and usable as a library today. |
| `crash-reporting` | Unwired — `CrashReportingModule` imported nowhere | `/crash-reporting` is not served; also opt-in and off by default. |
| `demos` | Unwired — `DemoModule` imported nowhere | `/v1/demo` and `/seed-reset` are **not served**, despite complete controllers, guards, and scheduler. |
| `reconciliation` | Conditional | Skipped when `SUPABASE_URL` points at localhost or 127.0.0.1. Drift detection does not run locally. |
| `notifications` | Conditional | Same condition. Webhooks and in-app notifications do not run locally. |
| `developer` | Conditional | Same condition. |
| `auth` | Library by design | Not in `app.module.ts`; two of its guards are registered globally there as `APP_GUARD` providers, and `AuthModule` is imported where the rest are needed. |
| `common/idempotency` | Library by design | `IdempotencyModule` is imported by `transactions` and `fiat-ramps` rather than registered globally. |
| `exports/export-storage` | Library by design | `ExportStorageModule` is imported by `exports` and `job-queue`. |

Modules that are **intentionally thin** — small on purpose, and not the place to grow a domain:

| Module | Why it is thin |
|---|---|
| `payments` | A single Horizon read with `since`/`limit` filtering. Despite the name it owns no payment domain logic — that lives in `links`, `transactions`, and `refunds`. |
| `dashboard-feed` | One endpoint. Deliberately an aggregator over other modules' repositories with no state of its own. |
| `types` | Ambient declarations only. Never add runtime code. |
| `manifests` | A pure diff function and a DTO. Correct as-is; it just needs wiring. |
| `soroban-tooling` | Two testnet helpers. Must never grow a mainnet path. |
| `developer` | A convenience layer over `api-keys` and `notifications`. Should not acquire its own persistent state. |
