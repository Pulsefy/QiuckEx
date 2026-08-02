# Capability Map: Live vs Mocked vs Partial vs Experimental

This document is the single place to check **what is actually built versus scaffolded** across all four product surfaces (`app/frontend`, `app/backend`, `app/mobile`, `app/contract`). Use it before picking an issue or building on top of an existing flow, so you don't depend on something that only *looks* implemented.

Companion docs:

- [BACKEND-CLIENT-CONTRACT-MAP.md](./BACKEND-CLIENT-CONTRACT-MAP.md) — endpoint-level wiring between clients and backend (mismatch numbers referenced below, e.g. "mismatch #1", come from that doc).
- [MVP-CONTRACT-SCOPE.md](./MVP-CONTRACT-SCOPE.md) — what is deliberately on-chain vs deferred.
- [RUNTIME-CONFIG-MATRIX.md](./RUNTIME-CONFIG-MATRIX.md) — environment/config drift that affects whether "Live" flows actually work in your environment.

## Status legend

Exactly four status terms are used in this document. If you update a row, use only these:

| Status | Meaning |
|---|---|
| **Live** | Wired end-to-end against real services (NestJS backend, Supabase, Horizon, Soroban RPC). Safe to build on. |
| **Partial** | Some segments are real, others are stubbed, missing, or broken. Read the notes column before relying on it. |
| **Mocked** | Returns hardcoded/simulated data. The UI or API shape exists, but nothing real happens behind it. |
| **Experimental** | Gated behind feature flags, testnet-only, or still at spec/requirements stage. Behavior may change or be disabled at any time. |

> "Planned but not fully wired" items from the contract map (client exists, backend route missing) are classified **Partial** here. Known-broken wiring is also **Partial**, with the breakage called out in the notes.

---

## Frontend (`app/frontend`)

Next.js 15 app. Base URL via `NEXT_PUBLIC_QUICKEX_API_URL` (`src/lib/api.ts`), default `http://localhost:4000`.

| Flow | Owning module | Status | Notes |
|---|---|---|---|
| Public profile page | `src/app/[username]` → backend `usernames` | **Live** | Real `GET /username/:username`; private profiles degrade correctly. |
| Pay page + SSR OG previews | `src/app/pay`, `src/lib/og-metadata.ts` → backend `links` | **Live** | Real `GET /payment-links/status`. |
| Payment signing state | `src/components/payment-states/ActivePaymentState.tsx` | **Mocked** | Fabricates a fake signed XDR string (L148–151); no real wallet signature is produced. |
| Link generator (assets, path preview, metadata, CSV bulk) | `src/app/generator` → backend `stellar`, `links` | **Live** | Real endpoints throughout; bulk gated by `bulk_link_generation` flag (enabled by default). |
| Link generator — Soroban contract preflight | `src/app/generator` → backend `stellar` | **Experimental** | `POST /stellar/soroban-preflight` requires `testnet.contract_writes` flag + `NetworkSafetyGuard`; 503 if `QUICKEX_CONTRACT_ID` unset. |
| Dashboard analytics | `src/app/dashboard`, `src/hooks/analyticsApi.ts` → backend `analytics` | **Live** | Real report/export; silently falls back to empty data on API failure. |
| Marketplace listings + detail | `src/app/marketplace` → backend `marketplace` | **Partial** | Listing fetch/detail hit real `GET /marketplace` routes, but see next two rows. |
| Marketplace — user bids & user listings | `src/hooks/marketplaceApi.ts` | **Mocked** | `MOCK_USER_BIDS` / `MOCK_USER_LISTINGS` returned behind fake delays. |
| Marketplace — real-time bid updates | `src/hooks/useRealtimeUpdates.ts` | **Mocked** | `MockWebSocket` class generates random bids on a timer; no server connection exists. |
| Marketplace — extend/cleanup contract actions | `src/hooks/mockApi.ts` | **Mocked** | `mockContractCall()` resolves `true` after a timeout. |
| Discovery page | `src/app/discovery` | **Mocked** | Renders `MOCK_USERS` from `src/lib/mockData.ts`. The backend already serves real `GET /username/search|trending|recently-active|featured` — wiring them up is an open opportunity. |
| Notification center | `src/app/notifications`, `src/components/NotificationCenterProvider.tsx` | **Partial** | UI is real but state is localStorage-only; not fed by the backend `notifications` module. |
| Webhook management | `src/app/webhooks` → backend `notifications` | **Live** | Full webhook CRUD/logs/redeliver/signature-verify family. |
| Developer settings (API keys) | `src/app/settings/developer` → backend `api-keys` | **Live** | Key CRUD, usage, rotate. |
| Profile settings | `src/app/settings` | **Mocked** | Save is a `// TODO: Call API to save profile`; nothing persists to the backend. |
| Team management | `src/app/settings/teams` | **Mocked** | In-memory member list and a hardcoded "admin" role; no backend module exists for teams. |
| Admin — system health | `src/components/admin/SystemHealth.tsx` → backend `health` | **Live** | `GET /health`. |
| Admin — feature flags & audit logs | `src/components/admin/*` → backend `feature-flags`, `audit` | **Partial** | Endpoints are real but called with **no auth header**, and the backend controllers are unguarded (mismatch #7 — known security gap). |

## Backend (`app/backend`)

NestJS app, ~38 modules wired in `src/app.module.ts`. Supabase (40 migrations) and Horizon integrations are real. `ReconciliationModule`, `NotificationsModule`, and `DeveloperModule` are skipped when `SUPABASE_URL` points at local Supabase.

| Flow / module | Owning path | Status | Notes |
|---|---|---|---|
| Usernames & public profiles | `src/usernames` | **Live** | Includes search/trending/featured endpoints that no client consumes yet. |
| Payment links (metadata, status, bulk, recurring, scam alerts) | `src/links` | **Live** | Recurring endpoints have no client consumer yet. |
| Transactions (Horizon-backed, compose/build/simulate) | `src/transactions` | **Live** | Compose/simulate writes are **Experimental** (flag-gated, see below). `build` is a compatibility alias of `compose`. |
| Recent payments | `src/payments` | **Live** | Thin controller over `HorizonService.getPayments`; no client consumer yet. |
| Stellar (verified assets, path payments, quotes) | `src/stellar` | **Partial** | Assets and path previews are Live; the quote **preflight is a stub that always reports feasible** (`quote.service.ts` L141). |
| Analytics (report, export, time-series) | `src/analytics` | **Live** | — |
| API keys | `src/api-keys` | **Live** | — |
| Notifications & webhooks | `src/notifications` | **Live** | Disabled in local dev (local Supabase check in `app.module.ts`). |
| Marketplace | `src/marketplace` | **Live** | Listings/detail only — no bids or real-time endpoints exist (frontend mocks those, see above). |
| Receipts | `src/receipts` | **Partial** | `receipts.service.ts` L206: `// TODO: replace with actual Supabase/database call`. |
| Reconciliation | `src/reconciliation` | **Partial** | Horizon-observed counts are placeholders that mirror expected values (`reconciliation.service.ts` L403–404) — it cannot detect real divergence yet. Disabled in local dev. |
| Fiat ramps (SEP-24 deposit/withdraw, KYC) | `src/fiat-ramps` | **Mocked** | Entire module: hardcoded MoneyGram/Banxa anchor list, fabricated interactive URLs, ack-only KYC/status callbacks. No real anchor or SEP-10 auth integration. |
| Contract registry | `src/contracts` | **Live** | ETag/304 support; admin-scoped writes/rollback. |
| Feature flags | `src/feature-flags` | **Live** | Supabase-backed with kill-switch semantics; controller is **unguarded** (mismatch #7). |
| Audit logs | `src/audit` | **Live** | Controller is **unguarded** (mismatch #7). |
| Ingestion (Soroban events) | `src/ingestion` | **Live** | Versioned event schemas with legacy-topic fallback. |
| Refunds, job queue, health, metrics | `src/refunds`, `src/job-queue`, `src/health`, `src/metrics` | **Live** | Mainnet refund initiation gated by `mainnet.refunds` flag (disabled by default). |
| Session bootstrap (`GET /session/bootstrap`) | — (no module) | **Partial** | Mobile client is wired; backend route does not exist (mismatch #2). |
| Feedback intake (`POST /feedback`) | — (no module) | **Partial** | Mobile client is wired with export fallback; backend route does not exist (mismatch #3). |

## Mobile (`app/mobile`)

Expo/React Native app, 25 screens in `app/mobile/app`. ⚠️ All "Live" rows are subject to base-URL drift: services default to `localhost:3000` (frontend's port) and `payment-confirmation.tsx` falls back to `api.quickex.com` (wrong TLD) — set `EXPO_PUBLIC_API_URL` explicitly (mismatch #4).

| Flow | Owning module | Status | Notes |
|---|---|---|---|
| Transaction history | `services/transactions.ts` → backend `transactions` | **Live** | Real Horizon-backed data. |
| Link creation & asset picker | `services/link-metadata.ts`, `app/link-generator.tsx` → backend `links`, `stellar` | **Live** | Same contracts as frontend. |
| In-app notification center | `services/in-app-notifications.ts` → backend `notifications` | **Live** | Defensively handles two response shapes (mismatch #8). |
| Local notification store | `services/notifications.ts` | **Partial** | Real API when online with a wallet session; seeds `MOCK_NOTIFICATIONS` on offline/error/no-session paths. |
| Escrow confirmation (contract registry sync) | `app/payment-confirmation.tsx`, `services/contract-registry.ts` | **Partial** | **Broken today**: calls `/api/contracts/registry` but the backend serves `/contracts/registry` — every sync 404s (mismatch #1, highest-value small fix). |
| Session bootstrap | `services/session-bootstrap.ts` | **Partial** | No backend route exists (mismatch #2). |
| In-app feedback | `services/feedback.ts`, `app/feedback.tsx` | **Partial** | No backend route; every submit silently degrades to the export path (mismatch #3). |
| Offline action queue | `services/offline-queue.ts` | **Partial** | Queue machinery is real; the built-in `mock-success`/`mock-failure`/`mock-payment` handlers are dev-only **Mocked** actions. |
| Contacts, security center, wallet session, local data | `services/contacts.ts`, `services/security*.ts`, `services/wallet-session.ts` | **Live** | Deliberately device-local (AsyncStorage/SecureStore); no backend sync by design. |
| Share receipt | `src/screens/ReceiptScreen.tsx` | **Live** | Builds a *web* share URL; does not consume the backend `GET /v1/receipts/*` API (which has no client consumer yet). |
| Debug screens (deep-link, notification, offline-queue inspector, QA checklist) | `app/*-debug.tsx`, `app/qa-smoke-checklist.tsx` | **Experimental** | Developer tooling; hidden in production+mainnet builds. |

## Contract (`app/contract`)

Monolithic Soroban contract `QuickexContract` (`contracts/quickex/src/lib.rs`). Deployed to **testnet** (ID via env / contract registry); **mainnet deployment is post-audit and has not happened** — see [MVP-CONTRACT-SCOPE.md](./MVP-CONTRACT-SCOPE.md).

| Capability | Owning module | Status | Notes |
|---|---|---|---|
| Escrow deposit / withdraw / commitments | `src/escrow.rs`, `src/commitment.rs`, `src/escrow_id.rs` | **Live** | Testnet only; extensive test suite (unit, fuzz, bench, upgrade). |
| Fee routing (basis points, per-asset overrides) | `src/fee` modules | **Live** | Static fees only. |
| Pause policy, emergency mode, admin/roles | `src/admin.rs`, `src/pause_policy.rs` | **Live** | Emergency mode is irreversible by design. |
| `create_escrow` counter endpoint | `src/lib.rs` (`create_escrow`) | **Mocked** | Only increments a counter; `_from`/`_to`/`_amount` params are reserved and ignored. |
| Oracle-priced dynamic fees | `src/oracle.rs` | **Mocked** | Explicit MVP stub; fees fall back to static basis points (deferred per scope doc). |
| Custom nonces/signatures, dispute arbitration, on-chain X-Ray privacy, hook registry | — | **Experimental** | Deliberately deferred out of MVP scope; partial primitives exist (privacy level storage, nonce checks) but are not product-complete. |
| M-of-N multisig governance | `.kiro/specs/governance-model-v1` | **Experimental** | Requirements-stage spec only; the deployed contract still uses single-admin + role separation. |
| SAC asset compatibility matrix | `.kiro/specs/sac-asset-compatibility-matrix` | **Experimental** | Spec formalizes existing `SUPPORTED_ASSETS` validation; not yet implemented as specified. |

## Feature-flag gates (Experimental switchboard)

Defaults from `app/backend/src/feature-flags/feature-flags.service.ts`:

| Flag | Default | Gates |
|---|---|---|
| `testnet.contract_writes` | enabled | `POST /transactions/compose\|build\|simulate`, `POST /stellar/soroban-preflight` |
| `mainnet.contract_writes` | **disabled** | All Soroban writes on mainnet |
| `mainnet.refunds` | **disabled** | Refund initiation on mainnet |
| `mainnet.dispute_actions` | **disabled** | Escrow dispute actions on mainnet |
| `bulk_invoicing_v2`, `bulk_link_generation` | enabled | Generator bulk flows |

A separate env-var rollback guard exists at `app/backend/flags.js` (`FEATURE_<NAME>=true`); it is unrelated to the flags module above.

## Contributor notes — do not rely on these yet

1. **Fiat on/off-ramps** (`app/backend/src/fiat-ramps`) — everything is fabricated, including the SEP-24 interactive URLs. Do not build UI assuming real anchor behavior.
2. **Marketplace bids / real-time updates** — there is no backend or WebSocket server behind them; the frontend generates the data locally.
3. **Frontend payment signing** — `ActivePaymentState.tsx` produces a fake XDR. No transaction is actually signed or submitted from that state.
4. **Reconciliation results** — observed values mirror expected values, so "everything reconciles" is not evidence of correctness.
5. **Stellar quote preflight** — always reports feasible; do not treat it as a real feasibility check.
6. **Mobile escrow registry sync** — 404s today due to the `/api` path prefix (mismatch #1). Fix the path before building on it.
7. **`admin/feature-flags` and `admin/audit`** — unguarded endpoints; adding guards must land together with auth-header changes in the frontend admin pages (mismatch #7).
8. **Mainnet anything on-chain** — the contract is not deployed to mainnet and all `mainnet.*` flags default to disabled. Treat all on-chain flows as testnet-only.
9. **Frontend discovery / profile settings / teams pages** — pure scaffolding on mock or in-memory data.
10. **Everything in `.kiro/specs/`** — requirements documents, not shipped behavior.

## How to use this map

- **Picking an issue?** "Mocked" rows paired with an existing Live backend module (e.g., discovery page vs the real `username/*` endpoints) are the highest-leverage wiring tasks.
- **Building on a flow?** Anything not marked **Live** needs the notes column read first; **Partial** rows tell you exactly which segment is missing.
- **Changing a flow's status?** Update the relevant row **in the same PR**, using only the four status terms defined above. If the change also touches endpoint wiring, update [BACKEND-CLIENT-CONTRACT-MAP.md](./BACKEND-CLIENT-CONTRACT-MAP.md) too.
