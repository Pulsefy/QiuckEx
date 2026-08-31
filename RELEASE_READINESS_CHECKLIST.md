# QuickEx Release Readiness Checklist (Testnet-First)

This checklist is the shared release gate for QuickEx across **backend, frontend, mobile, and contracts**. Every release candidate is validated on **testnet first**; mainnet promotion reuses the exact steps that passed on testnet.

Use this document as the single place to track cross-app release blockers. Copy the checklist into the release PR (or tracking issue) and check items off there so the sign-off is auditable.

Related documents:

- [RELEASE_PROMOTION_FLOW.md](RELEASE_PROMOTION_FLOW.md) — staging → production promotion mechanics
- [app/contract/documentation/deployment-checklist.md](app/contract/documentation/deployment-checklist.md) — contract-specific release gate
- [app/contract/documentation/deployment-playbook.md](app/contract/documentation/deployment-playbook.md) — deploy, key management, rollback, and mitigation playbook
- [app/mobile/RELEASE_CHECKLIST.md](app/mobile/RELEASE_CHECKLIST.md) — mobile pipeline, permissions, and privacy review
- [app/backend/SMOKE_TESTS.md](app/backend/SMOKE_TESTS.md) — smoke test suites and remote-target usage
- [docs/TESTNET-INCIDENT-RUNBOOK.md](docs/TESTNET-INCIDENT-RUNBOOK.md) — what to do when something breaks *after* release: detection signals, mitigation, and the specific tooling per scenario
- [docs/BACKEND-MODULE-MAP.md](docs/BACKEND-MODULE-MAP.md) — backend module ownership and allowed dependency directions

---

## 0. RC validation report (start here)

The backend aggregates the core testnet release signals into a single endpoint:

```
GET /admin/rc-validation/report   (admin API key required)
```

The report combines smoke/readiness probes, contract registry completeness, indexer lag, and environment parity into classified blockers with an overall `releaseReady` flag.

- [ ] `releaseReady: true` and `overallStatus: ready` (zero `critical` blockers)
- [ ] Any `warning`/`info` blockers are triaged and either resolved or explicitly accepted in the release PR
- [ ] The report `network` matches the target network for this release (testnet for RC validation)
- [ ] Report ID and timestamp are attached to the release PR for auditability

If the report is `blocked`, stop: resolve the listed blockers (each includes a remediation hint) before continuing.

## 1. Deploy artifacts

- [ ] Release WASM is built for the release commit (`cargo build --target wasm32v1-none --release`)
- [ ] Deployment ran through a tracked path — either [app/contract/scripts/deploy.sh](app/contract/scripts/deploy.sh) (emits `deployment-manifest.json`) or [app/backend/scripts/soroban-deploy.ts](app/backend/scripts/soroban-deploy.ts) (writes `app/backend/deployments/{network}-{contract}.json`)
- [ ] Manifest conforms to [manifest-schema.json](app/contract/documentation/manifest-schema.json); `contract_id` and `wasm_hash` match the actual deploy output
- [ ] Signed artifacts uploaded via `POST /contracts/deployment-artifacts` and downloadable with checksum verification
- [ ] For upgrades: testnet upgrade rehearsal completed via [testnet-upgrade-rehearsal.sh](app/contract/scripts/testnet-upgrade-rehearsal.sh) with rehearsal artifacts captured (before/after metadata, health check)

## 2. Registry state

- [ ] Deployment published to the backend contract registry (`POST /contracts/registry/publish`)
- [ ] `GET /contracts/registry` returns `authoritative: true` for the target network
- [ ] All contracts in `CONTRACT_REGISTRY_EXPECTED_SET` have active deployment entries (no `registry.missing-contracts` blocker)
- [ ] Registry entry (`contractId`, `wasmHash`, `contractVersion`, `schemaVersion`) matches the on-chain `get_deployment_metadata` output
- [ ] [environment-registry.toml](app/contract/documentation/environment-registry.toml) is updated for every affected network
- [ ] Registry ETag changed since the previous release (clients polling with `If-None-Match` will pick up the new deployment)

## 3. Smoke tests

- [ ] Backend smoke suite passes against the deployed testnet target:
  ```bash
  SMOKE_TEST_BASE_URL=<target-api-url> npm run test:smoke:all
  ```
  (covers health/readiness, network config, link metadata, discovery, rate limits, perf budgets)
- [ ] Soroban/Horizon smoke suite passes (`test:smoke:soroban` — RPC connectivity, tx simulation)
- [ ] No **critical** smoke failures (health, database, external services, network config, migrations) — these block the release outright
- [ ] Contract event-emission smoke test done on testnet: one known event-emitting action, payload includes `schema_version` and matches [events-schema.md](app/contract/docs/events-schema.md)
- [ ] Soroban E2E workflow ([soroban-e2e.yml](.github/workflows/soroban-e2e.yml)) is green for the release commit (requires `E2E_WALLET_SECRET` and `QUICKEX_CONTRACT_ID` secrets)

> Note: the automated post-deploy smoke workflow ([smoke-tests.yml](.github/workflows/smoke-tests.yml)) is currently disabled, so smoke runs must be executed and recorded manually until it is re-enabled.

## 4. Preview cleanup

Ephemeral contributor previews must not leak into a release:

- [ ] No stale branch previews remain active — run `POST /admin/branch-previews/cleanup-expired` or confirm the hourly auto-expiry sweep has run (reasons: `ttl_expired`, `inactivity` > `PREVIEW_INACTIVITY_THRESHOLD_MS`, `max_age` > `PREVIEW_MAX_AGE_MS`)
- [ ] `GET /admin/branch-previews?includeInactive=false` shows only previews that are intentionally still active
- [ ] Expired preview scopes are purged (daily cron calls `delete_expired_preview_scope_data`; verify no rows in `preview_scopes` past `expires_at`)
- [ ] Preview cache cleared for any branch being promoted (`POST /admin/branch-previews/:branchName/invalidate-cache`)
- [ ] The release branch itself is not mapped to a preview environment override

## 5. Frontend checks

### Runtime config

- [ ] Required env vars set per environment and passing `validateEnv()` ([src/lib/env.ts](app/frontend/src/lib/env.ts)): `NEXT_PUBLIC_QUICKEX_API_URL` (valid URL), `NEXT_PUBLIC_STELLAR_NETWORK` (`testnet`/`mainnet`), `NEXT_PUBLIC_SITE_URL`
- [ ] `NEXT_PUBLIC_CONTRACT_REGISTRY_VERSION` and `NEXT_PUBLIC_VERCEL_DEPLOYED_AT` are injected by CI so the deployment info panel reflects the release
- [ ] Staging banner renders on all non-mainnet environments ([StagingBanner.tsx](app/frontend/src/components/StagingBanner.tsx)) — verify visually on the staging deploy
- [ ] Frontend CI ([frontend-ci.yml](.github/workflows/frontend-ci.yml)) green: lint, type-check, build, npm audit, mixed-content (hardcoded `http://`) scan

### Theme regressions

- [ ] Light and dark themes verified on key pages (payment link, profile, settings) — no unstyled/flash-of-wrong-theme regressions from the theme init script in `layout.tsx`
- [ ] `ThemeToggle` switches and persists the theme correctly
- [ ] Any component changes touching theme tokens are visually reviewed in both modes (frontend currently has no automated theme snapshot tests — manual review is the gate)

## 6. Mobile checks

### Runtime config

- [ ] EAS profile matches the release intent ([eas.json](app/mobile/eas.json)): `dev`/`staging` → testnet, `production` → mainnet
- [ ] `app.config.ts` resolves the correct API URL, bundle identifier, and `STELLAR_NETWORK` for the selected `APP_ENV`
- [ ] Build metadata panel in Settings shows the correct version, build number, environment, network, and `BUILD_TAG` (branch-commit) for the installed build
- [ ] Install the internal build on Android and iOS and confirm the environment/network shown in-app match the intended target
- [ ] Full mobile pipeline/permissions/privacy items in [app/mobile/RELEASE_CHECKLIST.md](app/mobile/RELEASE_CHECKLIST.md) are complete

### Theme regressions

- [ ] Theme snapshot suite passes ([__tests__/theme-screenshots.test.tsx](app/mobile/__tests__/theme-screenshots.test.tsx) — light/dark/system) with no unexplained snapshot updates
- [ ] Snapshot diffs, if any, are intentional and reviewed as part of the release PR

## 7. Backend checks

- [ ] Backend CI green for the release commit; database migrations for the target environment applied exactly once (see [cd.yml](.github/workflows/cd.yml) `db:migrate` step)
- [ ] `GET /health` readiness probes all pass on the deployed target
- [ ] Environment parity checks pass (network configuration, Stellar/Supabase config, feature flags, base URL) — surfaced as the `environment` section of the RC validation report

### Indexer lag

- [ ] Indexer lag is within threshold: `lagLedgers <= indexerLagThresholdLedgers` (RC report `lag` section; blockers `lag.blocking` / `lag.lagging`)
- [ ] Indexer lag guard is **enabled** and **not overridden** in the target environment — an active override must be justified in the release PR
- [ ] Ingestion checkpoint for the QuickEx contract is advancing (compare against Horizon network head)

### Oracle readiness

- [ ] Oracle fee config state is known and intentional: the on-chain price fetch is currently a stub ([oracle.rs](app/contract/contracts/quickex/src/oracle.rs)), so dynamic USD fees **must** fall back to static basis points — confirm `fee_bps` values are correct for the release
- [ ] If an `OracleFeeConfig` is set, its `stale_threshold_secs` behavior is verified (stale/missing prices fall back safely, never block payments)
- [ ] Oracle failure harness tests pass (backend `oracle-failure.harness.unit.spec.ts` — Horizon path-finding outage, stale data, malformed responses)

### Route compatibility

- [ ] No breaking changes to public API routes or response shapes without a compatibility path (the backend has no URL versioning — removed/renamed routes break clients immediately)
- [ ] Event schema changes preserve `compatibleVersions` in [event-schema.ts](app/backend/src/ingestion/event-schema.ts) and the contract-side schema catalog lock test passes (`cargo test test_event_schema_catalog_locks_canonical_topics_and_payloads`)
- [ ] Legacy event-topic fallback in the Soroban event parser still handles events from the previous contract version during the rollover window
- [ ] Frontend and mobile clients built against the previous backend release still work against the new backend (spot-check the core payment flow)

## 8. Contract checks

- [ ] Required pre-deploy checks pass (see [deployment-checklist.md](app/contract/documentation/deployment-checklist.md) §1): `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `bench_`, `upgrade_harness_`, event-schema catalog lock test
- [ ] Upgrade safety gate tests pass (`cargo test upgrade_safety_gate_`) and, for upgrades, the ceremony order is planned: `set_upgrade_window` → `start_upgrade` → `upgrade` → `complete_upgrade` (invariants enforced, atomic rollback on failure)
- [ ] Post-deploy on-chain validation done: `health_check` OK and `get_deployment_metadata` matches the manifest/registry
- [ ] Governance requirements met: signer set documented, pause policy configured, admin/deploy key explicit in the PR

## 9. Reviewer sign-off

A release PR is mergeable only when:

- [ ] The RC validation report (ID + timestamp) is linked in the PR and shows `releaseReady: true`
- [ ] Testnet validation output (deploy manifest, smoke results, event smoke test) is attached or summarized in the PR
- [ ] At least one reviewer per affected surface has approved:
  - **Contracts** — a contract maintainer confirms deploy artifacts, registry entries, and upgrade-ceremony/rollback plan
  - **Backend** — a backend maintainer confirms migrations, indexer lag, route compatibility, and parity checks
  - **Frontend/Mobile** — an app maintainer confirms runtime config, staging banner/build metadata, and theme review
- [ ] Any accepted warnings or guard overrides are explicitly written down in the PR (who accepted, why, and follow-up issue if applicable)
- [ ] For mainnet promotion: governance approval is captured and the recorded testnet run is referenced, per the [mainnet release gate](app/contract/documentation/deployment-playbook.md)

## 10. Rollback references

Know the rollback path **before** shipping. In order of preference (mitigate before rolling back):

1. **Pause first**: `set_paused` (global) or `set_pause_flags` (per-feature); emergency mode as last resort — see [deployment-playbook.md §6](app/contract/documentation/deployment-playbook.md)
2. **Registry rollback**: `POST /contracts/registry/rollback` reverts the active registry entry to a prior version so clients resolve the previous contract
3. **Contract upgrade rollback**: `complete_upgrade` invariant failures roll back atomically; a follow-up upgrade ceremony can restore the previous WASM hash
4. **Frontend rollback**: revert to the previous Vercel deployment — see [VERCEL_DEPLOYMENT_GUIDE.md](app/frontend/VERCEL_DEPLOYMENT_GUIDE.md)
5. **Mobile**: internal-distribution builds can be superseded by re-issuing the previous build profile; production store rollouts should be halted before promoting a replacement

If an incident is already underway rather than anticipated, switch to the [Testnet Incident Response Runbook](docs/TESTNET-INCIDENT-RUNBOOK.md), which covers Soroban RPC outage, indexer lag, stuck payments, webhook backlog, and a bad contract deploy — including when to use the `testnet.contract_writes` write kill switch, and the reconciliation and support-bundle steps that close an incident out.

Pre-release rollback checklist:

- [ ] The previous known-good contract version/WASM hash is recorded and available in the registry history
- [ ] The rollback or pause path for this specific release is written in the release PR
- [ ] Monitoring hooks are in place for the rollout window: `health_check`, `get_deployment_metadata`, pause/upgrade events, schema-version mismatches, indexer lag metrics
- [ ] The on-call operator for the rollout window knows where the [incident runbook](docs/TESTNET-INCIDENT-RUNBOOK.md) is and holds an admin-scoped API key
