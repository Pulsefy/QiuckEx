# Backend Load Harness

Run the repeatable HTTP load profile against a running local, preview, or staging backend. The harness does not start a server or create blockchain data.

## Run

From the repository root:

```bash
BASE_URL=http://localhost:4000 PAYMENT_USERNAME=alice RECEIPT_TX_HASH=<testnet-tx-hash> pnpm --filter @quickex/backend perf:load
```

PowerShell:

```powershell
$env:BASE_URL="http://localhost:4000"; $env:PAYMENT_USERNAME="alice"; $env:RECEIPT_TX_HASH="<testnet-tx-hash>"; pnpm --filter @quickex/backend perf:load
```

The default profile runs link creation, payment-page reads, and transaction receipt reads for 30 seconds with four workers. Use `RECEIPT_ADDRESS` instead of `RECEIPT_TX_HASH` to exercise the address receipt path.

Useful settings are `CONCURRENCY`, `DURATION_SECONDS`, `WARMUP_SECONDS`, `REQUEST_TIMEOUT_MS`, `SCENARIOS` (comma-separated), `PAYMENT_AMOUNT`, `PAYMENT_ASSET`, `PAYMENT_MEMO`, `RESULTS_FILE`, and `CHECK_THRESHOLDS=false`. Results include throughput, p50/p95/p99 latency, status counts, and error rate.

## Baselines

Thresholds live in `load-baseline.json`. They are conservative starting points for local or preview environments. Use `CHECK_THRESHOLDS=false` while establishing a new environment baseline, then update the committed values from representative results. A threshold failure exits with status 1, so the command can be used as a performance gate without changing the existing CI workflow.

Rate-limited `429` responses are counted as errors. Configure the API key and throttling policy for the target environment before comparing results; do not hide rate limiting by treating it as success.

## Adding a scenario

1. Add the scenario name to `ScenarioName` and `parseScenarios` in `load-harness.ts`.
2. Add its request construction in `request`, including a stable fixture supplied through an environment variable.
3. Add its baseline thresholds to `load-baseline.json`.
4. Include its metrics in the existing report; the runner enforces the new thresholds automatically.

Keep scenarios read-only or idempotent where possible. A scenario that creates external state must use a dedicated test fixture and document cleanup requirements.