# Metrics module (BE-115: Endpoint Hardening & Label Cardinality Limits)

This module exposes the Prometheus `/metrics` endpoint and collects application
metrics. It is guarded by `MetricsGuard`, which requires the
`x-metrics-token` header to match `METRICS_ENDPOINT_TOKEN`. **Do not remove
the guard** — the endpoint must never be publicly exposed without
authentication or network restriction.

## Metric label cardinality (important)

Prometheus label **cardinality** is the number of distinct label *values* a
metric can take. Unbounded label values (payment IDs, usernames, contract IDs,
RPC endpoint URLs, free-form event names) cause the metrics database to grow
without bound, degrading the metrics backend and alerting.

### Rules for adding a new metric

1. **Never** use high-cardinality values directly as label values:
   - payment/transaction IDs
   - usernames / public keys
   - contract IDs
   - full URLs or endpoints
   - free-form strings (event names, tags, error messages)

2. **Add every label name to `BOUNDED_METRIC_LABELS`** in
   `metric-label-guard.ts` so the registration guard (`assertMetricLabelsBounded`,
   called from `MetricsService.onModuleInit`) accepts it.

3. If the label value is high-cardinality, **add it to `METRIC_LABEL_ALLOWLISTS`**
   with either:
   - an **empty allowlist** (`[]`) when the raw value must never be exposed —
     every value is bucketed under `METRIC_LABEL_OVERFLOW` (`"overflow"`); or
   - a **finite allowlist** of permitted values — any value outside the list is
     bucketed under the overflow bucket.

4. In the recording method, pass label values through `boundedMetricLabel(name, value)`
   before calling `.labels(...)`, e.g.:

   ```ts
   this.ingestionLagSeconds
     .labels(boundedMetricLabel('contract_id', contractId))
     .set(lagSeconds);
   ```

5. If a metric is added without a bounded label policy, the unit test suite
   (`metric-label-guard.unit.spec.ts`) fails — that is intentional. Register
   the label in the guard and re-run the tests.

### Example

```ts
// metric-label-guard.ts
export const METRIC_LABEL_ALLOWLISTS = {
  contract_id: [], // never expose raw contract ids
  status: ['completed', 'failed', 'pending', 'unknown'],
};

// metrics.service.ts
this.paymentsTotal.labels(boundedMetricLabel('status', status)).inc();
```

A raw `contract_id` like `CCEX1234567890` is recorded as `contract_id="overflow"`,
keeping cardinality bounded while preserving the alert signal.
