# Routing Conventions

How HTTP route prefixes are chosen in the QuickEx backend, and how the rule is
enforced. This is the reference for the agreed routing convention: which routes
are prefixed, which are versioned, and why.

## The convention

**A controller's `@Controller(...)` argument is its public route prefix.**

`app/backend/src/main.ts` intentionally does **not** call `setGlobalPrefix`, so
there is no hidden prefix between a controller and the URL. Whatever a
controller declares is what a client must call — which is exactly why the
prefixes need a rule: a client cannot infer a prefix that is not there.

Canonical prefixes are **unprefixed resource paths**:

| Shape | Example | Notes |
|---|---|---|
| Resource | `@Controller("contracts")` | Plural, lowercase, kebab-case. |
| Nested resource | `@Controller("links/recurring")` | Extra `/` segments, not `-`. |
| Admin / operator surface | `@Controller("admin/refunds")` | Reserved `admin/` namespace. |
| Sub-path on a resource | `@Controller("contracts/views")` | Fine when it owns no state of its own. |

Rules:

1. **No transport-environment prefixes.** `api/` and `mobile/` never appear in a
   route prefix. A route is a resource, not a client or an environment.
2. **URLs are unversioned.** The API version is declared once, in `main.ts`'s
   Swagger `DocumentBuilder` (`.setVersion("v1")`) and in the release process.
   New `v1/` prefixes are not allowed. If real URL versioning is ever adopted it
   is a single global mechanism applied in one place — not a `v1/` prefix on
   whichever controller needed it first. Existing versioned routes are
   grandfathered below.
3. **Lowercase, and plural for collections.** `admin/abuse-signals`, not
   `Admin/AbuseSignals`.
4. **`admin/` is the operator namespace.** Anything under `admin/` is expected
   to be guarded; see the auth notes in
   [`BACKEND-CLIENT-CONTRACT-MAP.md`](BACKEND-CLIENT-CONTRACT-MAP.md).
5. **A prefix is owned by one module.** Two controllers on the same prefix
   (`links` is currently shared by `links.controller.ts` and
   `scam-alerts.controller.ts`) make route collisions likely — check before
   adding a sub-route.

### Why it matters

The convention was not followed, and that drift is a direct contributor to the
mobile `/api/contracts/registry` 404: `v1/receipts` was versioned,
`api/environment-parity` was `api/`-prefixed, and every other controller was
unprefixed. With no rule to point at, a client reasonably assumed an `/api`
prefix existed. It did not.

## Exemptions (frozen)

Two closed sets are allowed to be non-canonical. **An entry may only be
removed, never added** — that is the whole point of writing them down. The unit
spec fails if either set drifts from these tables, in either direction.

### 1. Compatibility aliases

A non-canonical prefix kept for a client that already shipped against it. The
canonical prefix **must be registered alongside**, so dropping the alias later
is not a breaking change.

| Canonical | Alias retained | Controller |
|---|---|---|
| `contracts` | `api/contracts` | `src/contracts/contract-registry.controller.ts`, `src/contracts/contract-spec.controller.ts` |
| `contracts` | `mobile/contracts` | same |
| `contracts` | `api/mobile/contracts` | same |
| `seed-reset` | `api/seed-reset` | `src/demos/seed-reset.controller.ts` |

The `contracts` aliases exist because they shipped with the mobile 404 fix; they
are the reason a rule is now written down instead of discovered per incident.

### 2. Grandfathered versioned routes

Existing `v1/` routes with live callers. Kept exactly as they are so no client
breaks, but **no new `v1/` prefix may be created**, and a grandfathered
controller picks up its unprefixed canonical prefix (with the `v1/` prefix kept
as an alias) the next time that controller is touched.

| Prefix | Controller | Live callers |
|---|---|---|
| `v1/receipts` | `src/receipts/receipts.controller.ts` | perf harness; module currently not imported by `AppModule` |
| `v1/runtime-config` | `src/runtime-config/runtime-config.controller.ts` | `app/mobile/services/runtime-config.ts`, `app/mobile/services/VersionCheckService.ts` |
| `v1/network` | `src/config/network.controller.ts` | `app/frontend/src/services/bootstrap.service.ts`, `e2e/tests/theme-mocks.ts` |
| `v1/demo` | `src/demos/demo.controller.ts` | local/demo tooling only |
| `v1/contracts/views` | `src/contracts/views/contract-views.controller.ts` | no in-repo client |

`environment-parity` was **normalized** rather than aliased: it has no HTTP
client (it is reached through `EnvironmentParityService` server-side), so
`api/environment-parity` was dropped in favour of `environment-parity`.

## How it is enforced

The convention is checked mechanically, not by review alone. Both entry points
read every `src/**​/*.controller.ts` **from disk**, so a controller added later
is covered with nothing to register:

- **Unit suite** — `src/routing/route-conventions.unit.spec.ts`, run by
  `pnpm test:unit`. Fails on a non-canonical prefix, on a `*.controller.ts`
  with no `@Controller`, on a compatibility alias without a canonical partner,
  and on drift between the tables above and
  `src/routing/route-conventions.ts`.
- **Standalone** — `pnpm check:routes`
  (`scripts/check-route-conventions.ts`), for CI or a pre-commit hook.

The shared rules live in `src/routing/route-conventions.ts`
(`BANNED_PREFIX_SEGMENTS`, `COMPATIBILITY_ALIASES`,
`GRANDFATHERED_VERSIONED_PREFIXES`, `canonicalPrefixProblem`).

### Review checklist for a new controller

1. Prefix is an unprefixed resource path (no `api/`, `mobile/`, `v1/`).
2. `admin/` only if the controller is operator-facing and guarded.
3. The prefix is not already owned by another module.
4. If a route changes, **clients change in the same PR** — mobile
   (`app/mobile/services/`), frontend (`app/frontend/src/services/`), the perf
   harness (`app/backend/perf/load-harness.ts`), and `e2e/` are the known
   callers. Run `pnpm check:routes`.

## Related

- [`BACKEND-CLIENT-CONTRACT-MAP.md`](BACKEND-CLIENT-CONTRACT-MAP.md) — the
  client-to-route contract, including known mismatches.
- [`RUNTIME-CONFIG-MATRIX.md`](RUNTIME-CONFIG-MATRIX.md) — the "backend has no
  global route prefix" entry.
- [`BACKEND-MODULE-MAP.md`](BACKEND-MODULE-MAP.md) — which module owns a route.
