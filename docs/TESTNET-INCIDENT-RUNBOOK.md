# Testnet Incident Response Runbook

Substantial operational tooling exists in the backend — a contract-write kill switch, an indexer lag guard, dead-letter replay, support bundle export, reconciliation reports, an admin operations surface. This runbook says **which one to reach for, in what order, under pressure**.

It is written for testnet. Mainnet promotion reuses the same steps; where the two differ, the difference is called out.

Companion documents:

- [RELEASE_READINESS_CHECKLIST.md](../RELEASE_READINESS_CHECKLIST.md) — the pre-release gate. Most bad deploys are prevented there, not here.
- [BACKEND-MODULE-MAP.md](./BACKEND-MODULE-MAP.md) — which module owns which surface.
- [app/contract/documentation/deployment-playbook.md](../app/contract/documentation/deployment-playbook.md) — contract pause, upgrade ceremony, and key management.

---

## 0. First five minutes

Do these in order, before diagnosing anything. They take under a minute and they determine everything that follows.

```bash
export API=https://<backend-host>
export KEY=<admin-scoped API key>

curl -s $API/health                                          # is the process alive?
curl -s $API/ready                                           # which dependency is down? (503 = hard failure)
curl -s -H "X-API-Key: $KEY" $API/admin/operations/indexer    # indexer lag
curl -s -H "X-API-Key: $KEY" $API/admin/operations/webhooks   # webhook backlog
curl -s -H "X-API-Key: $KEY" $API/admin/operations/errors     # recent errors
```

`GET /ready` is the highest-value single call: it probes Supabase, Horizon, and Soroban RPC with per-dependency timeouts and returns 503 when a critical dependency has hard-failed. It tells you **which of the five scenarios below you are in**.

Then pick your scenario:

| Symptom | Scenario |
|---|---|
| `/ready` reports Soroban RPC unhealthy; simulate/submit failing | [§1 Soroban RPC outage](#1-soroban-rpc-outage) |
| `lagLedgers` above threshold; stale reads; guard rejections | [§2 Indexer lag](#2-indexer-lag) |
| Payments stuck `ACTIVE`; users report paid-but-not-credited | [§3 Stuck payments](#3-stuck-payments) |
| Webhook backlog growing; DLQ depth climbing | [§4 Webhook delivery backlog](#4-webhook-delivery-backlog) |
| Errors began at a deploy; contract calls failing broadly | [§5 Bad contract deploy](#5-bad-contract-deploy) |

**Two things to do in parallel with everything below:**

1. **Start an incident record** and note the time you began.
2. **Capture a support bundle now** — before mitigating. State you change is state you cannot diagnose later. See [§7](#7-post-incident).

---

## Reference: signals and controls

Every scenario draws from these. Bookmark this section.

### Metrics (`GET /metrics`)

| Metric | Reads on |
|---|---|
| `soroban_rpc_active_endpoint`, `soroban_rpc_failover_total` | RPC health and failover activity |
| `indexer_lag_ledgers`, `indexer_lag_guard_status`, `indexer_lag_guard_blocked_requests_total` | Indexer lag and guard enforcement |
| `ingestion_lag_seconds`, `soroban_indexer_unknown_schema_version_total` | Ingestion health; schema mismatch after a deploy |
| `webhook_retry_total`, `webhook_delivery_duration_seconds` | Webhook delivery health |
| `outbox_depth`, `outbox_dispatch_lag_seconds`, `outbox_dispatch_total` | Transactional outbox backlog |
| `reconciliation_drift_active`, `reconciliation_consecutive_failures` | Ledger-vs-database divergence |
| `error_total`, `http_requests_total`, `http_request_duration_seconds` | General error rate and latency |
| `abuse_signals_high_score_total`, `http_rate_limited_requests_total` | Abuse or load-driven incidents |

### Endpoints

All admin routes require an API key with the `admin` scope, sent as `X-API-Key`.

| Purpose | Endpoint |
|---|---|
| Liveness / readiness / public status | `GET /health`, `GET /ready`, `GET /status` |
| Consolidated operator view | `GET /admin/operations/{indexer,ingestion,webhooks,errors}` |
| Release-gate report | `GET /admin/rc-validation/report` |
| Support bundle | `GET /admin/support/bundle?includeRequestIds=true` |
| Feature flags / kill switch | `GET|PATCH /admin/feature-flags/:key` |
| Job queue | `GET /admin/jobs`, `GET /admin/jobs/dlq`, `GET /admin/jobs/metrics/summary` |
| Job recovery | `POST /admin/jobs/:id/retry`, `POST /admin/jobs/bulk-retry`, `POST /admin/jobs/:id/cancel` |
| Indexer recovery | `POST /indexer/reindex`, `GET /indexer/unparsed-events`, `POST /indexer/unparsed-events/replay`, `POST /indexer/unparsed-events/replay/batch` |
| Reconciliation | `GET /reconciliation/status`, `POST /reconciliation/trigger`, `GET /reconciliation/history`, `GET /reconciliation/unmatched`, `POST /reconciliation/backfill` |
| Webhook recovery | `POST /webhooks/:publicKey/:id/redeliver`, `GET /webhooks/:publicKey/:id/{logs,stats,attempts}` |
| Contract registry | `GET /contracts/registry`, `POST /contracts/registry/rollback` |

### Environment controls

Changing these requires a restart. Prefer the feature-flag kill switch, which does not.

| Variable | Effect |
|---|---|
| `INDEXER_LAG_THRESHOLD_LEDGERS` | Ledgers of lag before the guard considers the indexer behind |
| `INDEXER_LAG_GUARD_ENABLED` | Master switch for lag-based request rejection |
| `INDEXER_LAG_GUARD_OVERRIDE` | Bypass the guard while still measuring lag |
| `SOROBAN_RPC_URL`, `SOROBAN_RPC_URLS` | Primary and additional RPC endpoints for failover |
| `SOROBAN_RPC_TIMEOUT_MS`, `SOROBAN_RPC_MAX_RETRIES` | Per-request RPC timeout and retry budget (defaults 10000 / 3) |
| `RECONCILIATION_ENABLED`, `RECONCILIATION_CRON_EXPRESSION` | Scheduled reconciliation runs (default every 5 minutes) |
| `RECONCILIATION_DRIFT_COUNT_THRESHOLD`, `RECONCILIATION_DRIFT_AMOUNT_THRESHOLD_STROOPS` | When a run is classified as drift |
| `RECONCILIATION_CONSECUTIVE_FAILURE_ALERT_THRESHOLD` | Consecutive failed runs before alerting |
| `DLQ_MONITOR_ENABLED`, `DLQ_ALERT_DEPTH_THRESHOLD`, `DLQ_ALERT_AGE_THRESHOLD_MS` | Dead-letter alerting |

### ⚠️ Tooling that is not currently available

**Seed reset is not served.** `DemoModule` is not imported in [app.module.ts](../app/backend/src/app.module.ts), so `POST /seed-reset/trigger`, `POST /seed-reset/force`, `GET /seed-reset/status`, and the `/v1/demo` routes return 404 despite the controllers, guards, and scheduler existing. **Do not plan a recovery around seed reset.** If demo or testnet data must be reset during an incident, either wire `DemoModule` and deploy, or reset the data directly. The same applies to `receipts`, `manifests`, and `crash-reporting` — see [BACKEND-MODULE-MAP.md §5](./BACKEND-MODULE-MAP.md#5-status-summary).

**Reconciliation, notifications, and developer routes are skipped against a local Supabase.** If `SUPABASE_URL` points at `localhost` or `127.0.0.1`, those three modules are not registered. This affects local reproduction, not deployed environments.

---

## 1. Soroban RPC outage

The RPC endpoint is unavailable, timing out, or returning errors. Reads served from indexed data continue; anything that simulates or submits fails.

### Detection

- `GET /ready` reports the Soroban RPC check failing; returns 503 if it hard-failed.
- `soroban_rpc_failover_total` climbing; `soroban_rpc_active_endpoint` moving or pinned to a failing endpoint.
- Elevated `error_total`; `/transactions/compose`, `/simulate`, `/submit` and `/stellar/soroban-preflight` failing.
- User reports of failed preflight or payment composition.

The backend already fails over across the endpoints in `SOROBAN_RPC_URL` + `SOROBAN_RPC_URLS`, retrying up to `SOROBAN_RPC_MAX_RETRIES`. A rising `soroban_rpc_failover_total` with a stable error rate means failover is **working** — that is degradation, not an outage. Escalate when every endpoint is failing.

### Immediate mitigation

1. **Confirm the outage is upstream, not ours.** Query the RPC URL directly. If it responds, the problem is network or config on our side.

   ```bash
   curl -s -X POST $SOROBAN_RPC_URL -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
   ```

2. **Check whether an alternate endpoint is configured.** If `SOROBAN_RPC_URLS` holds only one entry, there is nothing to fail over to. Adding a second endpoint requires a restart — do it, and treat the single-endpoint configuration as a post-incident action item.

3. **Engage the write kill switch** if simulation failures are producing user-visible errors or partial state:

   ```bash
   curl -X PATCH $API/admin/feature-flags/testnet.contract_writes \
     -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
     -d '{"enabled": false}'
   ```

   `NetworkSafetyGuard` reads this flag **fresh on every request**, so it takes effect across all instances immediately — no restart, no cache wait. Contract-write routes then return 503 with `CONTRACT_WRITES_DISABLED` and a clear message, and every block is written to the audit log. See [§6](#6-the-write-kill-switch) for when this is the right call.

4. **Do not restart the backend to "clear" RPC errors.** Failover state is in-process and rebuilding it discards knowledge of which endpoints are unhealthy.

### Recovery

1. Confirm the RPC endpoint is healthy again.
2. Re-enable writes: `PATCH /admin/feature-flags/testnet.contract_writes` with `{"enabled": true}`.
3. Check whether the indexer fell behind during the outage → [§2](#2-indexer-lag).
4. Run reconciliation → [§7](#7-post-incident).

---

## 2. Indexer lag

The indexer has fallen behind the network. Reads backed by indexed data are stale; the guard may be rejecting lag-sensitive requests.

### Detection

- `GET /admin/operations/indexer` — `isLagging: true`, `lagLedgers` above `thresholdLedgers`.
- `indexer_lag_ledgers` rising steadily; `indexer_lag_guard_blocked_requests_total` climbing.
- `indexer_lag_guard_status` shows whether the guard is enabled, overridden, or off.
- `ingestion_lag_seconds` rising.
- 503s from routes decorated with `@RequiresIndexerLagCheck`.

Lag is measured by a one-minute cron comparing the network's latest ledger against the last indexed checkpoint. A single elevated sample is not an incident — a **sustained rise** is.

### Immediate mitigation

1. **Determine whether the indexer is stalled or merely slow.** Poll twice, a minute apart:

   ```bash
   curl -s -H "X-API-Key: $KEY" $API/admin/operations/indexer
   ```

   If `lastIndexedLedger` is unchanged, ingestion is **stalled** — go to step 2. If it is advancing but slower than the network, it is **catching up**; monitor and hold.

2. **Check the upstream the indexer reads from.** Ingestion polls Horizon and Soroban RPC and fails over across Horizon endpoints after three consecutive failures. If Horizon is the problem, this is really [§1](#1-soroban-rpc-outage) in a different coat.

3. **Look for parse failures.** A schema change can stall progress by quarantining events:

   ```bash
   curl -s -H "X-API-Key: $KEY" $API/indexer/unparsed-events
   ```

   A rising `soroban_indexer_unknown_schema_version_total` alongside a recent deploy points at [§5](#5-bad-contract-deploy).

4. **Decide about the guard.** The guard exists to stop serving stale data as if it were current.
   - **Leave it on** when stale reads could cause a user to pay twice or act on a wrong balance. Rejecting is correct.
   - **Override it** only when the lag is understood, bounded, and stale reads are less harmful than a full outage. `INDEXER_LAG_GUARD_OVERRIDE=true` keeps measuring but stops rejecting. **This requires a restart and is a deliberate decision to serve stale data — record it in the incident log with who approved it.**

5. **Reindex from a known-good ledger** if the checkpoint is corrupt or events were missed:

   ```bash
   curl -X POST $API/indexer/reindex -H "X-API-Key: $KEY" \
     -H 'Content-Type: application/json' -d '{"fromLedger": <ledger>}'
   ```

   Reindexing adds load. If lag is caused by the indexer struggling to keep up, reindexing will make it worse before it makes it better.

6. **Replay quarantined events** once the parser handles them:

   ```bash
   curl -s -H "X-API-Key: $KEY" $API/indexer/unparsed-events
   curl -X POST $API/indexer/unparsed-events/replay/batch -H "X-API-Key: $KEY"
   # or one at a time:
   curl -X POST $API/indexer/unparsed-events/<pagingToken>/replay -H "X-API-Key: $KEY"
   ```

### Recovery

1. `lagLedgers` back under `thresholdLedgers`, `isLagging: false`.
2. `GET /indexer/unparsed-events` empty, or the remainder is understood and triaged.
3. If `INDEXER_LAG_GUARD_OVERRIDE` was set, **unset it and restart**. An override left on is a silent, indefinite commitment to serving stale data.
4. Run reconciliation — a lag episode is exactly when database and ledger diverge.

---

## 3. Stuck payments

Payments are not reaching a terminal state: links stay `ACTIVE` after payment, or users report paying without being credited.

### Detection

- User reports of paid-but-not-credited.
- `reconciliation_drift_active` = 1, or unmatched entries accumulating in `GET /reconciliation/unmatched`.
- `outbox_depth` or `outbox_dispatch_lag_seconds` rising — state changed but downstream effects did not fire.
- `recurring_payment` jobs failing in `GET /admin/jobs/dlq`.

Link states are `DRAFT → ACTIVE → EXPIRED | PAID → REFUNDED`. "Stuck" means a payment landed on chain but the link never moved to `PAID`.

### Immediate mitigation

1. **Establish whether the payment is on chain.** If it is not, this is a client or submission problem, not a stuck payment — check [§1](#1-soroban-rpc-outage).

2. **Check indexer lag first.** The overwhelming majority of stuck payments are lag, not loss: the payment is on chain, the indexer has not caught up, and the state transition has not been triggered. Go to [§2](#2-indexer-lag) and come back. **Do not manually reconcile a payment while the indexer is behind** — you will race the indexer and may double-apply.

3. **Check the outbox.** A rising `outbox_depth` with a flat `outbox_dispatch_total` means state changes are staged but not dispatching — the side effects, not the state, are stuck.

4. **Check the job queue** for failed `recurring_payment` or related jobs:

   ```bash
   curl -s -H "X-API-Key: $KEY" "$API/admin/jobs/dlq?type=recurring_payment"
   ```

5. **Run reconciliation** to get an authoritative comparison of database against ledger:

   ```bash
   curl -X POST $API/reconciliation/trigger -H "X-API-Key: $KEY"
   curl -s -H "X-API-Key: $KEY" $API/reconciliation/status
   ```

6. **Work the unmatched queue.** Reconciliation surfaces records it could not match; auto-matching handles the mechanical cases.

   ```bash
   curl -s -H "X-API-Key: $KEY" $API/reconciliation/unmatched
   curl -s -H "X-API-Key: $KEY" $API/reconciliation/unmatched/<id>
   curl -X POST $API/reconciliation/auto-match/trigger -H "X-API-Key: $KEY"
   curl -X POST $API/reconciliation/unmatched/<id>/resolve -H "X-API-Key: $KEY" \
     -H 'Content-Type: application/json' -d '{"resolution": "..."}'
   ```

   Resolving an unmatched record is an **auditable financial action**. Record the reason. `POST /reconciliation/backfill` re-runs over a historical range when the gap predates the incident.

7. **Refunds are a last resort**, via `POST /admin/refunds` after checking eligibility. A refund is not a fix for a stuck payment — it is a decision to unwind one. Escalate before issuing refunds during an active incident: refunding a payment the indexer is about to reconcile creates a worse problem than the one you started with.

### Recovery

1. `reconciliation_drift_active` back to 0.
2. Unmatched queue empty or every remaining entry triaged with a recorded reason.
3. Affected links in the correct terminal state.
4. Manual resolutions listed in the incident record with actor and rationale.

---

## 4. Webhook delivery backlog

Outbound webhooks are queuing, retrying, or dead-lettering. Subscribers are not receiving events.

### Detection

- `GET /admin/operations/webhooks` — `totalPending` rising.
- `webhook_retry_total` climbing; `webhook_delivery_duration_seconds` degrading.
- DLQ alerts from the dead-letter monitor (depth over `DLQ_ALERT_DEPTH_THRESHOLD`, or oldest job older than `DLQ_ALERT_AGE_THRESHOLD_MS`); it logs on state transitions, so an alert means a *sustained* backlog.
- Subscriber reports of missing events.

### Immediate mitigation

1. **Determine the blast radius — one subscriber or all of them.**

   ```bash
   curl -s -H "X-API-Key: $KEY" $API/admin/jobs/metrics/summary
   curl -s -H "X-API-Key: $KEY" "$API/admin/jobs/dlq?type=webhook_delivery"
   ```

   Failures concentrated on one `publicKey` are a subscriber problem: their endpoint is down, slow, or rejecting signatures. Failures across all subscribers are ours.

2. **For a single failing subscriber**, inspect the delivery history:

   ```bash
   curl -s -H "X-API-Key: $KEY" $API/webhooks/<publicKey>/<id>/stats
   curl -s -H "X-API-Key: $KEY" $API/webhooks/<publicKey>/<id>/logs
   curl -s -H "X-API-Key: $KEY" $API/webhooks/<publicKey>/<id>/attempts
   ```

   Persistent 401/403 usually means a signature mismatch after a secret rotation. Timeouts mean their endpoint is slow. Neither is fixed by retrying harder — contact the subscriber.

3. **For a systemic backlog**, check whether job execution is healthy at all. If *every* job type is backed up, the problem is the queue or the database, not webhooks. Check `GET /ready` and Supabase health.

4. **Do not bulk-retry into a still-broken endpoint.** Retrying a large DLQ against a subscriber that is still down burns the retry budget and re-dead-letters everything. Confirm the endpoint is healthy first with a single retry:

   ```bash
   curl -X POST $API/admin/jobs/<id>/retry -H "X-API-Key: $KEY"
   ```

5. **Then drain the DLQ** once a single retry succeeds:

   ```bash
   curl -X POST $API/admin/jobs/bulk-retry -H "X-API-Key: $KEY" \
     -H 'Content-Type: application/json' \
     -d '{"type": "webhook_delivery", "limit": 100}'
   ```

   Drain in bounded batches and re-check depth between them. Replay is tracked (`GET /admin/jobs/:id/replays`) and rate-limited, so duplicate delivery is bounded — but subscribers should be treating webhook delivery as at-least-once regardless.

6. **Redeliver a specific event** when a subscriber needs one message rather than a drain:

   ```bash
   curl -X POST $API/webhooks/<publicKey>/<id>/redeliver -H "X-API-Key: $KEY" \
     -H 'Content-Type: application/json' -d '{"eventId": "<id>"}'
   ```

7. **Cancel jobs that must not be delivered** — for example, notifications for state that has since been reversed: `POST /admin/jobs/:id/cancel`.

### Recovery

1. `totalPending` back to baseline; DLQ depth for `webhook_delivery` at or near zero.
2. `webhook_retry_total` flat.
3. Any subscriber whose events were dropped rather than replayed has been told, explicitly.

---

## 5. Bad contract deploy

A newly deployed contract or registry change is causing failures — errors starting sharply at a deploy boundary.

### Detection

- Error rate steps up at a deploy timestamp rather than ramping.
- Contract calls failing broadly; simulation errors mentioning unknown methods or bad arguments.
- `soroban_indexer_unknown_schema_version_total` rising — the indexer is seeing events it does not recognise.
- `GET /admin/rc-validation/report` returns `blocked` or `releaseReady: false` where it previously passed.
- The method allowlist rejecting calls that previously succeeded.

**The deploy boundary is the diagnostic.** If errors began exactly when the registry moved, treat this as a bad deploy until proven otherwise. Do not spend twenty minutes debugging the application.

### Immediate mitigation

**Order matters. Stop the bleeding, then roll back, then investigate.**

1. **Engage the write kill switch first.** It is the fastest control available, needs no deploy, and prevents further writes against a suspect contract:

   ```bash
   curl -X PATCH $API/admin/feature-flags/testnet.contract_writes \
     -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
     -d '{"enabled": false}'
   ```

2. **Capture a support bundle before changing anything else** — it snapshots the registry state you are about to alter:

   ```bash
   curl -s -H "X-API-Key: $KEY" \
     "$API/admin/support/bundle?includeRequestIds=true" > incident-bundle.json
   ```

3. **Confirm what is actually deployed:**

   ```bash
   curl -s -H "X-API-Key: $KEY" $API/contracts/registry
   curl -s -H "X-API-Key: $KEY" $API/admin/rc-validation/report
   ```

4. **Pause the contract** if the contract itself is misbehaving rather than the registry pointing at the wrong thing — `set_paused` (global) or `set_pause_flags` (per-feature); emergency mode is a last resort. See [deployment-playbook.md §6](../app/contract/documentation/deployment-playbook.md).

5. **Roll back the registry.** This is the fastest recovery when the contract code is fine but the registry points at a bad version — clients resolve addresses through the registry, so reverting the entry redirects everyone to the previous contract without a client deploy:

   ```bash
   curl -X POST $API/contracts/registry/rollback -H "X-API-Key: $KEY" \
     -H 'Content-Type: application/json' \
     -d '{"name": "<contract-name>", "version": "<previous-version>"}'
   ```

   Rollback is audited and rate-limited. Contract-change webhooks fire, so subscribers learn the registry moved.

6. **If the contract itself is bad**, rollback is an upgrade ceremony, not an endpoint. `complete_upgrade` invariant failures roll back atomically; restoring a previous WASM hash requires a follow-up ceremony in the order `set_upgrade_window → start_upgrade → upgrade → complete_upgrade`. See the [deployment playbook](../app/contract/documentation/deployment-playbook.md) and [RELEASE_READINESS_CHECKLIST.md §10](../RELEASE_READINESS_CHECKLIST.md).

7. **Reindex after the registry settles** if the indexer quarantined events under the bad version. Replay from `/indexer/unparsed-events` once the parser recognises them → [§2](#2-indexer-lag).

### Escalation

**Escalate to a contract maintainer immediately** — before rolling back — if any of these hold. Registry rollback is safe and reversible; contract-level actions are not.

- The contract holds funds and the defect could affect balances.
- A pause or emergency-mode decision is required.
- An upgrade ceremony is needed to restore a previous WASM hash.
- This is mainnet.

### Recovery

1. `GET /contracts/registry` shows the intended version; `GET /admin/rc-validation/report` returns `releaseReady: true`.
2. Error rate back to the pre-deploy baseline.
3. Writes re-enabled: `PATCH /admin/feature-flags/testnet.contract_writes` with `{"enabled": true}`.
4. Indexer caught up and unparsed events cleared.
5. Reconciliation run clean.

---

## 6. The write kill switch

`testnet.contract_writes` is the single fastest lever in the system. Know when to pull it.

**How it works.** `NetworkSafetyGuard` gates every route decorated with `@RequiresFlag(TESTNET_CONTRACT_WRITES_FLAG)`. Unlike normal flag evaluation, the guard calls `evaluateFlagFresh` — an **uncached read on every request** — so a flip propagates across all instances immediately. Blocked requests get a 503 with code `CONTRACT_WRITES_DISABLED` and a message directing the user to retry after the incident. Every block is written to the audit log with the actor, path, and reason.

**It only applies on testnet.** The guard returns early when `config.isTestnet` is false. On mainnet, use contract-level pause instead.

```bash
# Disengage writes
curl -X PATCH $API/admin/feature-flags/testnet.contract_writes \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{"enabled": false}'

# Re-enable
curl -X PATCH $API/admin/feature-flags/testnet.contract_writes \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{"enabled": true}'
```

**Use it when:**

- A bad contract deploy is suspected — **first action, before diagnosis** (§5).
- Writes are producing partial or inconsistent state.
- Reconciliation shows active drift and continued writes would widen the gap.
- You need a stable system to diagnose against.

**Do not use it for:**

- Read-only degradation. It gates writes only; disabling it does not help a read outage.
- Indexer lag on its own — the lag guard is the targeted control, and it already rejects only the affected routes.
- A single failing subscriber or job type. Cancel or pause that work instead.

**Before flipping it back on:** the root cause is understood, the registry points at the intended version, the indexer has caught up, and a reconciliation run is clean. Re-enabling into an unresolved fault re-creates the incident with more damage.

---

## 7. Post-incident

### Collect a support bundle

If you did not capture one during the incident, capture one now. It is the sanitised diagnostic snapshot — network config, contract registry state, indexer status and checkpoints, and recent errors, with secrets and PII redacted:

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/admin/support/bundle?includeRequestIds=true" > incident-<date>-bundle.json
```

`includeRequestIds=true` correlates errors with traces and is what you want for an incident record; it defaults to `false` because request IDs may carry context you would not want in a public issue. Attach the bundle to the incident record and to any GitHub issue. `POST /support/bundle-references` registers a bundle so an issue can cite it without re-exporting.

### Reconcile

**Every incident that touched writes, the indexer, or the contract registry ends with a reconciliation run.** This is the check that money and state agree.

```bash
curl -X POST $API/reconciliation/trigger -H "X-API-Key: $KEY"
curl -s -H "X-API-Key: $KEY" $API/reconciliation/status
curl -s -H "X-API-Key: $KEY" $API/reconciliation/history
curl -s -H "X-API-Key: $KEY" $API/reconciliation/unmatched
```

If the incident spanned a period the scheduled runs missed, backfill it:

```bash
curl -X POST $API/reconciliation/backfill -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"fromLedger": <start>, "toLedger": <end>}'
```

The incident is not closed until `reconciliation_drift_active` is 0 and the unmatched queue is empty or every remaining entry is triaged with a recorded reason.

### Close-out checklist

- [ ] Support bundle captured and attached to the incident record.
- [ ] Reconciliation run clean; unmatched queue empty or triaged.
- [ ] **Every temporary control reverted** — kill switch re-enabled, `INDEXER_LAG_GUARD_OVERRIDE` unset, paused contracts unpaused, cancelled jobs accounted for. Left-on overrides are the most common way one incident becomes the next.
- [ ] Audit log reviewed for the incident window (`GET /admin/audit`) — it holds every privileged action taken, including automated kill-switch blocks.
- [ ] `GET /admin/rc-validation/report` returns `releaseReady: true`.
- [ ] Timeline written: detection time, actions with timestamps, who decided what.
- [ ] Manual resolutions and refunds listed with actor and rationale.
- [ ] Detection gaps filed — if you found this from a user report rather than a metric, the missing alert is an action item.
- [ ] If tooling was missing or broken during the incident, file it. Seed reset being unserved is already known; add anything else you hit.
