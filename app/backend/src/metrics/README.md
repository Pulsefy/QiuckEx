# Metrics Module & Prometheus Hardening

Application metrics collection, Prometheus endpoint exposure, access control, and label cardinality safety.

## Overview

The `metrics` module registers application-level Prometheus metrics (counters, histograms, gauges) and exposes them at the `/metrics` endpoint.

To protect Prometheus backends from memory exhaustion and destabilization due to high cardinality, all dynamic or user-controlled label dimensions are guarded with bounded allowlists and an explicit overflow bucket (`"other"`).

---

## Access Control & Endpoint Hardening

The Prometheus scraping endpoint `GET /metrics` is protected by `MetricsGuard`.

- **Authentication Header**: `X-Metrics-Token: <token>`
- **Configuration**: Set `METRICS_ENDPOINT_TOKEN` in your environment.
- **Fail-Closed Security**: If `METRICS_ENDPOINT_TOKEN` is unset or empty, `MetricsGuard` automatically rejects all requests with `401 Unauthorized` to avoid exposing internal performance or operational data to the public internet.

---

## Safe Metric Registration & Label Cardinality Guidelines

### Why Cardinality Protection is Mandatory

In Prometheus, each unique combination of key-value label pairs creates a new time series in memory. If labels accept unbounded inputs (such as user IDs, transaction hashes, arbitrary contract addresses, or free-form user tags), the time-series count will explode, destabilizing both the backend and Prometheus.

### Rules for Metric Labels

1. **Never use high-cardinality values directly as label values**:
   - ❌ User IDs / Stellar public keys (`G...`)
   - ❌ Transaction hashes (`0x...`)
   - ❌ Payment link IDs / Quote IDs
   - ❌ User-submitted free-form strings or tags
   - ❌ Raw URLs with unbounded path parameters or query strings

2. **Always restrict dynamic label dimensions using `sanitizeLabel`**:
   - Every label dimension that accepts input from external sources or domain events must be matched against a compile-time allowlist in `label-allowlist.ts`.
   - Any value not present in the allowlist is converted to the overflow sentinel `"other"`.

### How to Add a New Metric Safely

Follow this step-by-step checklist when adding a new metric:

1. **Define the Metric in `MetricsService`**:
   - Choose the appropriate metric type (`Counter`, `Gauge`, `Histogram`).
   - Limit `labelNames` to the minimal necessary bounded dimensions (ideally $\le 3$ labels).
   ```typescript
   this.paymentVolume = new client.Counter({
     name: "payment_volume_total",
     help: "Total payments processed by asset and status",
     labelNames: ["asset", "status"],
   });
   ```

2. **Define or Extend Allowlists in `label-allowlist.ts`**:
   - If the label can take arbitrary string values, define an allowlist constant:
   ```typescript
   export const ALLOWED_PAYMENT_ASSETS = ["XLM", "USDC", "EURC"] as const;
   ```

3. **Apply `sanitizeLabel` in the Recording Method**:
   ```typescript
   recordPayment(asset: string, status: string, amount: number) {
     if (!this.initialized || !this.paymentVolume) return;
     try {
       this.paymentVolume
         .labels(
           sanitizeLabel(asset, ALLOWED_PAYMENT_ASSETS),
           sanitizeLabel(status, ALLOWED_PAYMENT_STATUSES),
         )
         .inc(amount);
     } catch (error) {}
   }
   ```

4. **Add Unit Tests in `metrics.cardinality.unit.spec.ts`**:
   - Assert that allowlisted values pass through unchanged.
   - Assert that unlisted / malicious / unbounded values are converted to `"other"`.
   - Ensure the `[CARDINALITY CONTRACT]` test verifies unbounded values are rejected.

---

## File Reference

- [`metrics.service.ts`](./metrics.service.ts): Central metric registry and recording methods.
- [`label-allowlist.ts`](./label-allowlist.ts): Allowlist constants and `sanitizeLabel()` overflow utility.
- [`metrics.guard.ts`](./metrics.guard.ts): Fail-closed token guard for `/metrics`.
- [`metrics.controller.ts`](./metrics.controller.ts): HTTP controller exposing Prometheus scraping endpoints.
- [`metrics.cardinality.unit.spec.ts`](./metrics.cardinality.unit.spec.ts): Cardinality enforcement and guard tests.
