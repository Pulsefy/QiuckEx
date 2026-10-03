# QuickEx Operations & Runbook

This operations runbook details incident response procedures, monitoring metrics, and critical route protection guardrails.

## Indexer Lag Guard Protection

The `IndexerLagGuard` protects endpoints that read indexed Stellar data (transactions, transaction timeline, dashboard feed, reconciliation reports, and payment receipts) against serving stale or incorrect data when the Horizon indexer falls behind the live network ledger.

### Protected Route Inventory

| Route | Method | Description | Failure Mode |
| :--- | :--- | :--- | :--- |
| `/transactions` | `GET` | Paginated indexed transactions | Fail closed (503 + `Retry-After: 60`) |
| `/transactions/timeline` | `GET` | Transaction timeline history | Fail closed (503 + `Retry-After: 60`) |
| `/dashboard/feed` | `GET` | Aggregated user activity feed | Fail closed (503 + `Retry-After: 60`) |
| `/reconciliation` | `GET` | Financial & balance drift reports | Fail closed (503 + `Retry-After: 60`) |
| `/receipts/:id` | `GET` | Cryptographically verified receipts | Fail closed (503 + `Retry-After: 60`) |

### Metrics & Monitoring
- `indexer_lag_ledgers`: Current ledger difference between Horizon network head and last indexed checkpoint.
- `indexer_lag_guard_blocked_requests_total`: Total count of requests blocked by the guard, labeled by method and route.
- `indexer_lag_guard_status`: Status gauge (`0` = disabled, `1` = enabled/healthy, `2` = overridden, `3` = lagging/blocking).

### Emergency Override
If an operational emergency requires bypassing the lag guard temporarily, set the configuration flag `INDEXER_LAG_GUARD_OVERRIDE=true` or update environment variables, which sets the guard status metric to `2` and allows requests to pass through.