# Feature Flags: Contributor Guide

This guide covers how QuickEx feature flags work, how to name and add one, who
may change them, and when to delete them. Read it before you add, modify, or
remove a flag.

**Source of truth**

| Piece | Location |
|---|---|
| Flag record type and DTOs | [`app/backend/src/feature-flags/feature-flags.dto.ts`](../app/backend/src/feature-flags/feature-flags.dto.ts) |
| `DEFAULT_FLAGS` registry, evaluation, cache, store fallback | [`app/backend/src/feature-flags/feature-flags.service.ts`](../app/backend/src/feature-flags/feature-flags.service.ts) |
| Admin and evaluate endpoints | [`app/backend/src/feature-flags/feature-flags.controller.ts`](../app/backend/src/feature-flags/feature-flags.controller.ts) |
| Route gating (`@RequiresFlag` + `NetworkSafetyGuard`) | [`requires-flag.decorator.ts`](../app/backend/src/feature-flags/requires-flag.decorator.ts), [`network-safety.guard.ts`](../app/backend/src/feature-flags/network-safety.guard.ts) |
| Persistent store (`feature_flags` table) | [`app/backend/supabase/migrations/`](../app/backend/supabase/migrations/) |
| Admin UI | [`app/frontend/src/components/admin/FeatureFlags.tsx`](../app/frontend/src/components/admin/FeatureFlags.tsx) |

---

## 1. How flags are resolved

Each backend instance builds a flag set on every cache miss:

1. **Bootstrap layer.** `DEFAULT_FLAGS` in the service, optionally overlaid by
   the `FEATURE_FLAGS_BOOTSTRAP_JSON` env var (a JSON array of partial flag
   records, keyed by `key`).
2. **Store layer.** Rows from the Supabase `feature_flags` table. A stored row
   **replaces** the bootstrap entry with the same key.
3. **Fallback.** If the store is unreachable, the bootstrap layer is used alone
   (`source: "bootstrap"`, `storeAvailable: false`). Writes through
   `PATCH /admin/feature-flags/:key` then fail with `503
   FEATURE_FLAG_STORE_UNAVAILABLE`, which keeps the safe defaults in force.

The result is cached per instance for `FEATURE_FLAGS_CACHE_TTL_MS`. Other
instances therefore see a change only after their cache expires. The one
exception is `testnet.contract_writes`: `NetworkSafetyGuard` reads it with
`evaluateFlagFresh()`, which bypasses the cache so the kill switch takes effect
on every instance at once.

**An unknown key always evaluates to disabled** (`reason: "missing-flag"`). The
system fails closed.

---

## 2. Record fields

Every flag is a `FeatureFlagRecord`. All fields are required in `DEFAULT_FLAGS`.

| Field | Type | Meaning |
|---|---|---|
| `key` | string | Stable identifier. Never rename a key; add a new flag instead (see §3). |
| `name` | string | Human-readable label shown in the admin UI. |
| `description` | string | One sentence that says what turning the flag **on** allows. |
| `enabled` | boolean | Master switch for the feature. |
| `killSwitch` | boolean | Emergency override. When `true`, the flag is off regardless of every other field. |
| `rolloutPercentage` | 0–100 | Share of users who get the feature once it is enabled. |
| `allowedUsers` | string[] | User IDs that bypass the rollout percentage (max 500). |
| `environments` | string[] | `NODE_ENV` values where the flag can be on (`development`, `test`, `production`). An empty list means every environment. |
| `metadata` | object | Structured tags. Required keys are listed below. |
| `updatedAt` / `updatedBy` | string | Set automatically on update. Use `new Date(0).toISOString()` and `'bootstrap'` in `DEFAULT_FLAGS`. |

### Required `metadata` keys for new flags

| Key | Required | Example | Purpose |
|---|---|---|---|
| `owner` | yes | `"backend"`, `"payments"`, a GitHub handle | Who is accountable for cleanup. |
| `issue` | yes | `"#412"` | The issue or PR that introduced the flag. |
| `removeBy` | yes, except permanent operational flags | `"2026-12-31"` | Target date for deletion (see §6). |
| `highRisk` | yes, if the flag gates mainnet funds or contract writes | `true` | Triggers the stricter review in §5. |
| `flow` / `surface` | recommended | `"refunds"`, `"links/bulk"` | The product area the flag gates. |
| `network` | when network-specific | `"testnet"` | Documents which Stellar network the flag targets. |
| `permanent` | for operational flags only | `true` | Marks a kill switch that is never deleted (see §6). |

> Flags that predate this guide (`bulk_invoicing_v2`, `bulk_link_generation`,
> and the `mainnet.*` / `testnet.*` gates) do not have `owner`, `issue`, or
> `removeBy`. Add these keys the next time you touch one of those flags.

---

## 3. Naming convention

- Keys are lowercase `snake_case` segments joined by dots:
  `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`.
- **Network safety gates** start with the Stellar network they protect:
  `mainnet.<flow>`, `testnet.<flow>` (for example `mainnet.refunds`). Do not use
  these prefixes for anything else.
- **Product and rollout flags** use `<surface>.<feature>`, for example
  `links.recurring_links` or `dashboard.earnings_chart`. The older unprefixed
  keys (`bulk_link_generation`, `bulk_invoicing_v2`) stay as they are, because
  renaming a key breaks stored rows and callers.
- Describe the capability, not the rollout state. Use
  `links.recurring_links`, not `enable_recurring_links_beta`.
- Do not add a version suffix (`_v2`) unless the new flag replaces a live flag
  and both must exist during the migration. Delete the old flag afterward.
- Never reuse a deleted key. Old audit logs and stored rows refer to it.

---

## 4. `enabled` vs `killSwitch` vs `rolloutPercentage`

Evaluation in `evaluateFlagFromSnapshot()` runs in this order. The first
matching rule decides the result.

| # | Check | Result | `reason` |
|---|---|---|---|
| 1 | Flag not found | off | `missing-flag` |
| 2 | `killSwitch === true` | off | `kill-switch` |
| 3 | `enabled === false` | off | `disabled` |
| 4 | `environments` is non-empty and does not include the current env | off | `environment-mismatch` |
| 5 | `userId` is in `allowedUsers` | **on** | `allowlist-match` |
| 6 | `rolloutPercentage >= 100` | on | `enabled` |
| 7 | `rolloutPercentage <= 0` | off | `rollout-miss` |
| 8 | No `userId` supplied | off | `missing-user-context` |
| 9 | `sha256(key:userId)` bucket is below `rolloutPercentage` | on / off | `rollout-match` / `rollout-miss` |

The three controls have different jobs:

- **`enabled`** is the normal on/off switch. The feature owner uses it to launch
  or pause a feature.
- **`killSwitch`** is for incidents. It takes priority over `enabled`, the
  allowlist, and the rollout. An operator can arm it during an incident without
  losing the configured rollout, and disarm it afterward to restore the exact
  prior state. Do not use it as a second "off" button during normal work.
- **`rolloutPercentage`** only applies after `enabled` is `true`. Bucketing is
  deterministic per `(key, userId)`, so the same user always gets the same
  result, and raising the percentage only adds users. Partial rollouts
  (1–99) need a `userId`. Callers that cannot supply one always get the
  feature off.

Two consequences to keep in mind:

- `allowedUsers` bypasses the percentage but **not** the kill switch,
  `enabled`, or `environments`.
- `environments` is matched against the backend's `NODE_ENV`, not the Stellar
  network. Network-specific behaviour comes from `NetworkSafetyGuard` (§7).

---

## 5. Who may add, modify, or remove a flag

| Action | Who | Required review |
|---|---|---|
| Add or remove a **standard** flag in `DEFAULT_FLAGS` | Any contributor, via PR | 1 maintainer approval |
| Add, remove, or change the defaults of a **high-risk** flag (`metadata.highRisk: true`, any `mainnet.*` key, or anything behind `NetworkSafetyGuard`) | Maintainers only | 2 maintainer approvals, one from a backend owner. The PR must state the safe default and name the routes it gates. |
| Toggle `enabled`, change `rolloutPercentage` or `allowedUsers` at runtime (standard flag) | Flag owner or an operator with admin access | None beyond the automatic audit entry |
| Set `enabled: true` on a **high-risk** flag in production | Operator with admin access | Written sign-off from a second maintainer (in the release issue or incident channel) **before** the change. Link it from the release notes. |
| Arm `killSwitch` | Any operator with admin access, at any time | None in advance. Post in the incident channel afterward. |
| Disarm `killSwitch` on a high-risk flag | Operator with admin access | Incident lead confirms the cause is resolved |

Rules that apply to every change:

- **Safe defaults.** A new high-risk flag ships with `enabled: false`,
  `rolloutPercentage: 0`, and a Supabase seed migration that uses
  `ON CONFLICT (key) DO NOTHING`, so it never overwrites a value an operator has
  already set. See
  [`20260528000001_network_safety_gate_flags.sql`](../app/backend/supabase/migrations/20260528000001_network_safety_gate_flags.sql).
- **Audit trail.** Every `PATCH /admin/feature-flags/:key` writes a
  `feature_flag.updated` entry (before/after snapshot) to `admin_audit_logs`.
  Set the `x-admin-actor` header to your real identity. The dashboard sends
  `admin-dashboard`, and the fallback is `admin-ui`.
- **Admin endpoint access.** The `admin/feature-flags` routes do not have their
  own auth guard in the controller. They must only be reachable through the
  protected admin surface. Do not expose them publicly, and do not add
  consumer-facing reads to the `admin/` path.

---

## 6. Deletion and cleanup policy

A flag is temporary unless it has `metadata.permanent: true`. Permanent flags
are operational kill switches such as `testnet.contract_writes` and the
`mainnet.*` gates.

**When a flag must be deleted**

- **Fully rolled out:** the flag has been `enabled: true`,
  `rolloutPercentage: 100`, and `killSwitch: false` in production for **two
  consecutive releases or 30 days, whichever is longer**, with no rollback. It
  must be removed within the following release.
- **Permanently disabled:** the feature has been abandoned, or the flag has been
  off in every environment for 30 days with no plan to ship. Remove the flag and
  the dead feature code together.
- **Past `removeBy`:** the owner either deletes the flag or pushes the date in a
  PR that explains why.

**How to delete (order matters)**

Stored rows override bootstrap entries, and a missing key evaluates to **off**.
If you delete the flag first, a fully rolled-out feature switches off. Follow
this order instead:

1. **Remove every read.** Delete the `@RequiresFlag(...)` decorators,
   `assertActionEnabled(...)` / `evaluateFlag(...)` calls, and any frontend or
   mobile checks. For a rolled-out flag, keep the "on" branch. For a disabled
   flag, delete the feature code. Ship this change.
2. **Remove the definition.** In a later PR, delete the entry from
   `DEFAULT_FLAGS`, drop it from any `FEATURE_FLAGS_BOOTSTRAP_JSON` values, and
   add a migration that runs `DELETE FROM feature_flags WHERE key = '<key>';`.
   Removing the entry from `DEFAULT_FLAGS` alone is not enough, because a stored
   row keeps the flag visible in the admin UI.
3. **Clean up tests** that refer to the key, including
   `feature-flags.service.unit.spec.ts`.

Keep the `admin_audit_logs` history. Do not delete it.

---

## 7. Related controls that are not ordinary flags

QuickEx has four layers that can block a write. They are independent. A request
must pass **all** of them, and turning one "on" never overrides another.

| Layer | Where | Scope | Who changes it |
|---|---|---|---|
| **Ordinary feature flags** | `FeatureFlagsService`, `feature_flags` table | Backend product behaviour | Admin API / dashboard (§5) |
| **Network safety gates** | `NetworkSafetyGuard` + `@RequiresFlag` | Backend routes. `mainnet.*` flags are checked only when the backend is **not** on testnet. `testnet.contract_writes` is checked only **on** testnet, with a fresh read. | Same admin API, high-risk rules |
| **Contract method allowlist** | `ContractMethodAllowlistGuard`, `CONTRACT_METHOD_ALLOWLIST_JSON` | Which `contractId`/`method` pairs the backend will compose or simulate | Environment config and redeploy |
| **On-chain pause policy and emergency allowlist** | [`app/contract/contracts/quickex/src/pause_policy.rs`](../app/contract/contracts/quickex/src/pause_policy.rs) | The Soroban contract itself | Contract admin transaction |

### Admin feature-flags controller

`GET /admin/feature-flags`, `GET /admin/feature-flags/:key`, and
`PATCH /admin/feature-flags/:key` are the only way to change flags at runtime.
They operate on ordinary flags **and** network safety gates, because both are
stored in the same table. The admin controller cannot change the contract
method allowlist or on-chain pause state.

### Emergency-entrypoint allowlist (on-chain)

The contract has its own pause controls, and they are not feature flags:

- **Global pause** and **granular pause flags** (`Deposit`,
  `DepositWithCommitment`, `Withdrawal`, `Refund`, `SetPrivacy`) are reversible
  and set by the contract admin.
- **Emergency mode** (`activate_emergency_mode`) is **irreversible**. Once it
  is active, only entry points where `EntryPoint::is_emergency_safe()` returns
  `true` can run: `Withdraw`, `Refund`, `StealthWithdraw`, `CleanupEscrow`, and
  `ExtendEscrowTtl`. Every deposit, dispute, and privacy entry point, and every
  admin/config mutation, is rejected with `ContractPaused`.
  `is_entry_allowed_in_emergency(entry)` exposes the allowlist for reads.

How this interacts with backend flags:

- Enabling a backend flag does **not** unlock a paused or emergency-blocked
  entry point. The contract rejects the call regardless.
- Being emergency-allowlisted on-chain does **not** enable the backend route.
  For example, during emergency mode refunds are allowed by the contract, but
  on mainnet the backend still blocks them while `mainnet.refunds` is disabled.
  If the incident plan relies on users recovering funds through QuickEx, an
  operator must enable the matching `mainnet.*` gate (with high-risk sign-off)
  and make sure its `killSwitch` is **not** armed.
- Do **not** add a backend flag that tries to mirror or override the emergency
  allowlist. Changes to the on-chain allowlist are contract changes: they need a
  contract PR, updates to `pause_policy_test.rs`, and a contract deployment.

---

## 8. Worked example: adding `links.recurring_links`

This example adds a standard (not high-risk) flag that gates a new
recurring-payment-link endpoint and its UI.

### Step 1: Register the flag in the backend

Add an entry to `DEFAULT_FLAGS` in `feature-flags.service.ts`. Start it **off**
so merging the PR changes nothing:

```ts
{
  key: 'links.recurring_links',
  name: 'Recurring Payment Links',
  description: 'Allows creating recurring (subscription) payment links.',
  enabled: false,
  killSwitch: false,
  rolloutPercentage: 0,
  allowedUsers: [],
  environments: ['development', 'test', 'production'],
  metadata: {
    owner: 'payments',
    issue: '#512',
    removeBy: '2027-03-31',
    surface: 'links/recurring',
  },
  updatedAt: new Date(0).toISOString(),
  updatedBy: 'bootstrap',
},
```

Optionally add a seed migration so the flag appears in the store (and the admin
UI) before anyone toggles it:

```sql
-- app/backend/supabase/migrations/<timestamp>_links_recurring_links_flag.sql
INSERT INTO feature_flags (key, name, description, enabled, kill_switch,
  rollout_percentage, allowed_users, environments, metadata, updated_by)
VALUES ('links.recurring_links', 'Recurring Payment Links',
  'Allows creating recurring (subscription) payment links.',
  false, false, 0, '[]'::jsonb,
  '["development","test","production"]'::jsonb,
  '{"owner":"payments","issue":"#512","removeBy":"2027-03-31","surface":"links/recurring"}'::jsonb,
  'system')
ON CONFLICT (key) DO NOTHING;
```

### Step 2: Enforce it on the server

The server is the security boundary. Client-side checks only hide UI. In the
service that handles the request:

```ts
await this.featureFlagsService.assertActionEnabled('links.recurring_links', {
  userId,
});
```

This throws `503 { error: 'FEATURE_DISABLED', flag, reason }` when the flag is
off. It follows the pattern in `bulk-payment-links.service.ts`. Pass `userId`
so partial rollouts work.

(For a **high-risk mainnet** flow, decorate the route with
`@UseGuards(NetworkSafetyGuard)` and `@RequiresFlag('mainnet.<flow>')` instead,
as in `refunds.controller.ts`.)

Add unit tests that cover off, kill-switch, allowlist, and rollout cases, in the
style of `feature-flags.service.unit.spec.ts`.

### Step 3: Expose it to clients

Web and mobile clients read flags through a **public, read-only** endpoint.
They must never call `admin/feature-flags`.

- **Available today:** `GET /feature-flags/:key/evaluate?userId=<id>` returns
  `{ key, enabled, reason, source }` for one flag.
- **Planned snapshot endpoint:** a single read that returns
  `Record<string, boolean>` of evaluated results for the caller. The mobile
  client already expects this shape as the `featureFlags` field of
  `GET /session/bootstrap` (see
  [`app/mobile/services/session-bootstrap.ts`](../app/mobile/services/session-bootstrap.ts)).
  That backend route and a shared frontend flag provider do not exist yet. When
  they are built, they should return **evaluated booleans only**, never raw
  records, so `allowedUsers` and `metadata` do not leak to clients.

### Step 4: Consume it in the frontend

Until a shared provider exists, evaluate the flag where it is needed and treat
any failure as **off**:

```tsx
const [recurringEnabled, setRecurringEnabled] = useState(false);

useEffect(() => {
  const url = `${getQuickexApiBase()}/feature-flags/links.recurring_links/evaluate` +
    (userId ? `?userId=${encodeURIComponent(userId)}` : "");
  fetch(url, { cache: "no-store" })
    .then((res) => (res.ok ? res.json() : { enabled: false }))
    .then((body) => setRecurringEnabled(Boolean(body.enabled)))
    .catch(() => setRecurringEnabled(false));
}, [userId]);

if (!recurringEnabled) return null;
```

### Step 5: Consume it in mobile

Read the flag from the session bootstrap payload and default to `false` when
the key is absent:

```ts
const bootstrap = await fetchSessionBootstrap(apiUrl);
const recurringEnabled = bootstrap.featureFlags["links.recurring_links"] === true;
```

### Step 6: Roll out

1. In staging, set `enabled: true` and add internal testers to `allowedUsers`.
2. In production, set `enabled: true` with `rolloutPercentage: 10`, then raise it
   to 50 and 100 while you watch error rates. The dashboard toggles `enabled`
   and `killSwitch`. Set the percentage and allowlist through
   `PATCH /admin/feature-flags/links.recurring_links`:

   ```bash
   curl -X PATCH "$API/admin/feature-flags/links.recurring_links" \
     -H "Content-Type: application/json" \
     -H "x-admin-actor: <your-handle>" \
     -d '{"enabled": true, "rolloutPercentage": 10}'
   ```

3. If something breaks, arm `killSwitch`. This keeps the rollout settings so you
   can resume from the same point.

### Step 7: Clean up

After 100% for two releases or 30 days, follow §6: remove the checks from steps
2, 4, and 5 first, then delete the `DEFAULT_FLAGS` entry and the stored row.

---

## 9. PR checklist for a new flag

- [ ] Key follows §3 and is not a reused key.
- [ ] All record fields are set. `metadata` includes `owner`, `issue`, and
      `removeBy` (or `permanent: true`).
- [ ] Default is off (`enabled: false`, `rolloutPercentage: 0`).
- [ ] The server enforces the flag, not just the UI.
- [ ] Clients treat a missing key or fetch error as off.
- [ ] Unit tests cover the off and on paths.
- [ ] High-risk flags: `metadata.highRisk: true`, a seed migration with
      `ON CONFLICT DO NOTHING`, 2 maintainer approvals, and the gated routes
      listed in the PR.
