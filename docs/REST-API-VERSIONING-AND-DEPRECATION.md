# REST API Versioning & Deprecation Policy

How the QuickEx backend introduces breaking changes, deprecates a route, and communicates sunset
dates to integrators: the **frontend** (`app/frontend`), **mobile** (`app/mobile`), users of the
generated **`@quickex/api-client`**, and **external API-key integrators**.

Scope: the NestJS REST surface documented in
[BACKEND-CLIENT-CONTRACT-MAP.md](./BACKEND-CLIENT-CONTRACT-MAP.md). On-chain event schemas are
governed separately by the `compatibleVersions` lists in
`app/backend/src/ingestion/event-schema.ts` and `app/contract/docs/events-schema.md`.

## 1. The versioning model

- **One API version: `v1`, declared once.** The version string lives in `app/backend/src/main.ts`
  (`DocumentBuilder().setVersion("v1")`) and nowhere else. Per
  [Routing Conventions](./ROUTING-CONVENTIONS.md), **URLs are unversioned**: no new `v1/`
  prefixes on controllers, and existing versioned routes are a frozen, grandfathered set.
- **The OpenAPI document is the contract of record.** `app/backend/docs/openapi.yaml` (served at
  `GET /docs`) is committed, and `packages/api-client` is generated from it
  (`pnpm api-client:generate`); CI (`.github/workflows/api-client.yml`) fails when the spec and
  the client drift. Any contract change ships with the regenerated spec in the same PR.
- **Consequence:** there is no "v2 URL" to hide behind. Breaking changes are introduced either by
  *adding* a new canonical route alongside the old one (and later retiring the old one, §4) or
  through the deprecation process below. A live route never changes in a breaking way without the
  notice period in §3.

## 2. Breaking vs. non-breaking changes (for this codebase)

**Rule of thumb:** if a client generated from today's `openapi.yaml` stops compiling, or a request
that succeeds today would start failing, it is **breaking** → §3 applies.

### Non-breaking (ship freely; still update the contract map in the same PR)

| Change | Notes for this repo |
|---|---|
| Adding a new endpoint | Add to the contract map's endpoint tables. |
| Adding a **new optional** request field or query param | Existing clients keep working. |
| Adding a new response field | Integrators must ignore unknown fields — mobile already tolerates this on `/notifications/in-app`. |
| Loosening validation | Accepting input that was previously rejected. |
| Adding a new API-key scope **that no existing route requires** | `API_KEY_SCOPES` is append-only in effect. |
| Adding response capabilities such as ETag/`304` alongside old behavior | Precedent: `GET /contracts/registry`. |
| Adding a new error `code` value | Clients must treat an unknown `code` as a generic failure and must not branch on exhaustiveness. |
| Raising a documented rate limit | e.g. `X-API-Key` tiers on `POST /links/metadata` (20 → 120 req/min). |
| Docs, tests, internal refactors with identical wire behavior | — |

### Breaking (requires the §3 deprecation process)

| Change | Notes for this repo |
|---|---|
| Removing or renaming a route, or changing its HTTP method | Includes retiring any route listed in the contract map's compatibility-alias or frozen tables. |
| Making an optional request field required, renaming request fields, or tightening validation | A previously accepted request returning `VALIDATION_ERROR` is a break, even with the same status-code family. |
| Removing/renaming a response field, or changing its type or meaning | e.g. the `PaymentLinkStatusDto` status values, `NormalizedReceipt` fields. |
| Changing pagination or cache semantics | Cursor/limit behavior on `transactions`/`marketplace`; the `ETag`/`If-None-Match` protocol on `/contracts/registry` is part of the contract once documented. |
| Changing the error envelope `{ code, message, fields? }` | Global `ValidationPipe` output shape. |
| Changing documented status-code expectations | Clients rely on 429/502/503 semantics from `transactions`. |
| **Adding auth where there was none** | e.g. adding `ApiKeyGuard`/`@RequireScopes` to the unguarded `admin/feature-flags` / `admin/audit` controllers (contract map mismatch #7) — must ship with the client change in the **same PR**. |
| Requiring a **new** scope on an existing route | Changing scope semantics is breaking API-wide ([BACKEND-MODULE-MAP.md](./BACKEND-MODULE-MAP.md), `auth`/`api-keys`). |
| Lowering a documented rate limit or quota | External integrators cannot code around this in a coordinated deploy. |
| Adding a value to a **response** enum/union | Breaks exhaustive `switch`es and the generated union types in `packages/api-client/src/schemas.d.ts`; do it via §3 with first-party clients updated in the same PR. |
| Repurposing an existing error `code` | Same code, different meaning, is a silent break. |
| Removing a compatibility alias | §4 governs. |

## 3. Deprecation lifecycle & notice period

**Minimum notice period: 90 calendar days.** For every externally reachable route (public or
API-key-guarded), at least 90 days must pass between the announcement (§3.1 step 1) and the earliest
removal date. Dates are fixed at announcement; they may only be **extended** later (extending is
always non-breaking).

| Milestone | When | What happens |
|---|---|---|
| T-0 — announce | Day 0 | Changelog entry (§7), `Deprecation`/`Sunset` headers live, `deprecated: true` in OpenAPI, contract map updated, integrator notices sent. |
| First-party cutover | Same PR or same week | `app/frontend`, `app/mobile`, `app/backend/perf`, `e2e/`, `packages/*` callers move to the replacement. First-party clients never wait out the 90 days — per [Routing Conventions](./ROUTING-CONVENTIONS.md), clients change in the same PR as the route. |
| Reminder 1 | T-30 (Day 60) | Direct notice to API-key owners whose keys called the route recently (§6). |
| Reminder 2 | T-7 (Day 83) | Final notice, same audience. |
| Earliest removal | Day ≥ 90 | Removal PR (§4, §5). |

- **Exception — emergencies only:** a security fix or kill-switch event may remove behavior
  immediately. The PR must still land a changelog entry marked `emergency` and a security advisory.
  The `MOBILE_MIN_SUPPORTED_VERSION` / `mobileVersionPolicy` lever (`GET /v1/runtime-config`) can
  force-upgrade **shipped mobile builds**; there is no equivalent lever for API keys, which is
  exactly why the 90-day floor exists for external integrators.
- **Aliases ship pre-deprecated:** a compatibility alias (§4) is marked `deprecated: true` in
  OpenAPI from the day it exists, but its 90-day removal clock starts only when a §7 changelog entry
  gives it a removal date.

### 3.1 How a deprecated route is marked — all three, in the same PR

**1. Response headers** on every response from the route (set centrally by a response interceptor
in `common`, which per [BACKEND-MODULE-MAP.md](./BACKEND-MODULE-MAP.md) owns cross-cutting
behavior):

```http
Deprecation: @1792454400
Sunset: Mon, 18 Jan 2027 00:00:00 GMT
Link: <https://github.com/Pulsefy/QiuckEx/blob/main/docs/REST-API-VERSIONING-AND-DEPRECATION.md#7-api-changelog>; rel="deprecation"
```

- `Deprecation` — structured-field date (RFC 9745): `@<unix-seconds>` of the announce date.
- `Sunset` — IMF-fixdate HTTP-date (RFC 8594) of the earliest removal date; **never earlier than
  the `Deprecation` date**, and ≥ 90 days after it.
- `Link` with `rel="deprecation"` — points at the §7 changelog entry with migration notes.

The route's behavior is otherwise unchanged while deprecated: deprecation is a notice, not a
failure (RFC 9745 §1).

**2. OpenAPI annotation** — on the handler:

```typescript
@ApiOperation({
  deprecated: true,
  description: "Deprecated 2026-10-20; sunset 2027-01-18. Use POST /transactions/compose (identical body and response).",
})
```

Then regenerate and commit the spec in the same PR: `pnpm api-client:generate` (CI fails if
`app/backend/docs/openapi.yaml` is stale). Generated clients surface the operation as deprecated,
which is compile-time visibility for `@quickex/api-client` users.

**3. Changelog** — an entry in [#7-api-changelog](#7-api-changelog) with: route, announce date,
sunset date, replacement route, migration notes. The
[BACKEND-CLIENT-CONTRACT-MAP.md](./BACKEND-CLIENT-CONTRACT-MAP.md) alias/endpoint tables are
updated in the same PR — the map is what contributors read first.

## 4. Compatibility aliases: introducing and retiring

The mechanics live in [Routing Conventions](./ROUTING-CONVENTIONS.md) (the frozen alias table);
this section defines the lifecycle policy.

### Introducing an alias

1. **Only for clients that already shipped.** Never introduce an alias for a new feature — new
   features get one canonical route.
2. **Canonical route is registered alongside the alias in the same PR**, and the alias handler
   delegates to the same service method (precedent: `POST /transactions/build` →
   `TransactionsService.composeTransaction()`, the `api/contracts` / `mobile/contracts` prefixes on
   the contract-registry controller).
3. **Prefix-level aliases must be registered** in `COMPATIBILITY_ALIASES`
   (`app/backend/src/routing/route-conventions.ts`). `pnpm check:routes` and
   `src/routing/route-conventions.unit.spec.ts` fail if an alias exists without a canonical
   partner — dropping the alias later is then mechanically guaranteed not to be a breaking change.
4. The alias is marked `deprecated: true` in OpenAPI from day one, documented in the contract map's
   compatibility-alias table, and noted in §7.

### Retiring an alias

1. **Confirm no first-party callers:** grep `app/frontend`, `app/mobile`, `app/backend/perf`,
   `e2e/`, and `packages/*` for the exact path.
2. **Deprecate the alias per §3.1** — headers, `deprecated: true`, and a §7 entry that names the
   removal date (≥ 90 days out). If access-log/usage telemetry still shows external traffic when
   the date arrives, **extend it** (another 30 days minimum) and update the entry; never remove a
   route that still has measured traffic.
3. **Removal PR:** delete the alias handler, remove its entry from `COMPATIBILITY_ALIASES` (entries
   may only be removed, never added — that is the point of the frozen table), update the contract
   map and §7, regenerate the spec.
4. **Tombstone for one extra window (30 days):** keep the path returning
   `410 Gone` with the standard envelope so integrators can distinguish a removed route from a typo:

   ```json
   { "code": "ROUTE_REMOVED", "message": "POST /transactions/build was removed on 2027-01-18; use POST /transactions/compose" }
   ```

   Then delete the tombstone and record it in §7.

## 5. Worked example: deprecating `POST /transactions/build` end-to-end

`POST /transactions/build` (`app/backend/src/transactions/transactions.controller.ts`) is a
deliberate alias of `POST /transactions/compose` — both invoke
`TransactionsService.composeTransaction()` and return unsigned XDR + `correlationId`. A repo-wide
grep shows no first-party caller; it exists for integrators built against older docs. Deprecating
it:

**PR 1 — announce (Day 0 = 2026-10-20, earliest removal 2027-01-18)**

- `@ApiOperation({ deprecated: true, ... })` on the `build` handler with the replacement in the
  description (identical request/response — the migration is a path swap).
- Interceptor emits on `/transactions/build` responses:
  `Deprecation: @1792454400`, `Sunset: Mon, 18 Jan 2027 00:00:00 GMT`, and the
  `Link: ...; rel="deprecation"` header from §3.1.
- §7 changelog entry: announce 2026-10-20, sunset 2027-01-18, replacement `POST /transactions/compose`.
- Contract map's compatibility-aliases bullet flips to *"`build` is deprecated — sunset 2027-01-18;
  use `compose`"*.
- `pnpm api-client:generate`, commit `openapi.yaml`.
- **Verify:** `curl -sI` the route and confirm the three headers; `pnpm check:routes` and
  `pnpm test:unit` green (the alias is a method-path alias, not a prefix entry, so the frozen table
  is untouched).

**PR 2 — first-party sweep (same week)**

- Repo grep (above) finds no frontend/mobile/perf/e2e caller, so there is nothing to migrate today;
  if one existed it moves to `/transactions/compose` **in the same PR**, which is a path-only change
  because both handlers share the service method.

**Day 0 / Day 60 / Day 83 — notify integrators** per §6: changelog, live headers, developer
dashboard notice, direct notices to owners of keys that called the route in the previous 30 days.

**PR 3 — remove (on or after 2027-01-18)**

- Replace the handler with the `410 Gone` tombstone from §4 step 4 (kept until 2027-02-17).
- §7 gains a *removed* entry; the contract map bullet flips to *removed*;
  `pnpm api-client:generate` regenerates the spec (the operation disappears);
  `pnpm check:routes` + `pnpm test:unit` green.
- **2027-02-17:** delete the tombstone, final §7 note.

**Rollback:** sunset dates only move later. If integrators report breakage after removal, restore
the handler with its deprecation headers and extend §7 — that path is always non-breaking.

## 6. How API-key integrators are notified of upcoming breaking changes

Every breaking change uses all five channels, in this order of authority:

| # | Channel | Backed by | Status |
|---|---|---|---|
| 1 | **API changelog** (§7) — single source of truth | this file, linked from `README.md` and the contract map | exists |
| 2 | **`Deprecation` / `Sunset` / `Link` headers** on the affected route | response interceptor in `common` (§3.1) | lands with the first deprecation PR |
| 3 | **OpenAPI `deprecated: true`** at `GET /docs` and in `app/backend/docs/openapi.yaml` | regenerated `@quickex/api-client`, enforced by CI | exists |
| 4 | **Developer dashboard notice** where keys are managed (`app/frontend/.../settings/developer/page.tsx`) | per-key usage already tracked on `ApiKeyRecord` (`request_count`, `last_used_at`) | required from the first external deprecation |
| 5 | **Direct notice to key owners** at T-0, T-30, T-7 | `owner_id` / `organization_id` on `ApiKeyRecord`, delivered through the `notifications` module (in-app channel; webhook delivery by adding an `api.deprecation_notice` event to `WEBHOOK_EVENTS` in `app/backend/src/notifications/dto/webhook.dto.ts`) | required from the first external deprecation |

- **Dashboard rule:** if a route carries a `Deprecation` header and an organization's keys called it
  in the last 30 days, the developer settings page must show a notice naming the route, its sunset
  date, and the replacement.
- **Machine-readers come first:** integrators are expected to discover deprecations from headers in
  production traffic even if they never read the docs — headers are on every response from day 0,
  not just at the sunset edge.
- **Emergency removals** compress the window: GitHub security advisory + a §7 entry marked
  `emergency`, no 90-day wait.

## 7. API changelog

Append-only, newest first. Every deprecation, removal, extension, and alias introduction gets one
entry in the PR that makes the change.

| Announced | Change | Route(s) | Earliest removal | Replacement | Notes |
|---|---|---|---|---|---|
| — | *No entries yet: the first is added by the first deprecation PR (§5, PR 1).* | | | | |

Entry template:

```markdown
| YYYY-MM-DD | deprecated / removed / extended / alias-introduced | METHOD /path | YYYY-MM-DD | METHOD /path | link to migration notes, PR |
```

## Related

- [BACKEND-CLIENT-CONTRACT-MAP.md](./BACKEND-CLIENT-CONTRACT-MAP.md) — client-to-route contract;
  updated in the same PR as any deprecation/removal.
- [ROUTING-CONVENTIONS.md](./ROUTING-CONVENTIONS.md) — prefix rules, the frozen compatibility-alias
  table, and enforcement (`pnpm check:routes`).
- [BACKEND-MODULE-MAP.md](./BACKEND-MODULE-MAP.md) — which module owns a route; `auth`/`api-keys`
  scope semantics.
- `app/backend/docs/openapi.yaml` + `packages/api-client/README.md` — the generated contract and its
  CI regeneration flow.
