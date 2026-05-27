# PR: FE-31 — Contract Registry Consumption (No Hardcoded Contract IDs)

## Summary

This PR implements changes required for FE-31: consume the Contract Registry instead of using hardcoded contract IDs. It centralizes contract ID lookup and removes brittle hardcoded values.

## Changes

- Replaced hardcoded contract IDs with calls to the Contract Registry resolution utility.
- Updated ingestion and reconciliation services to use registry lookups.
- Added unit tests and adjusted mocks where necessary.

Files touched (representative):

- `app/backend/src/ingestion/soroban-event.parser.ts`
- `app/backend/src/reconciliation/reconciliation.service.ts`
- `app/backend/src/transactions/horizon.service.ts`
- `app/backend/package.json`

## Motivation

Hardcoded contract IDs are error-prone and require manual updates when contracts change. Using the Contract Registry improves maintainability and supports dynamic contract deployments.

## How to test

1. Install dependencies and build the backend.

```bash
cd app/backend
pnpm install
pnpm build
pnpm test
```

2. Run unit tests for modified modules:

```bash
pnpm test -- -t "soroban-event.parser" || true
pnpm test -- -t "reconciliation.service" || true
```

3. (Optional) Run integration/e2e scenarios described in `app/backend/test/` to validate registry lookups during ingestion.

## QA / Reviewer Notes

- Confirm registry lookup fallback behavior for missing entries.
- Check caching/TTL behavior (if any) to ensure performance.
- Validate tests cover both success and failure registry responses.

## Rollout / Deployment Notes

- No immediate migration required; system falls back to configured defaults where applicable.
- Monitor ingestion and reconciliation logs for lookup failures after deployment.

## Related

- Issue/Task: FE-31

---
_Generated PR document for branch `feat/FE-31-contract-registry`._
