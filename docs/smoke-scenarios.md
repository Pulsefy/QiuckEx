# QuickEx Post-Deploy Smoke Scenarios

## Overview

Smoke scenarios define the canonical specification for post-deployment contract verification on testnet and mainnet. They cover core contract entry points, happy-path contract lifecycle operations, and explicit rejection paths.

By executing these scenarios against a newly deployed QuickEx Soroban contract instance, deployment pipelines can automatically verify that:
1. All core contract entry points are callable and responsive.
2. Contract behavior and state transitions conform to the canonical specification.
3. Validation rules and rejection paths return expected error codes without behavior drift.

---

## Machine-Readable Artifact

The scenario specification is exported as a stable, machine-readable JSON artifact:

- **Primary Path**: [`docs/smoke-scenarios.json`](file:///Users/NKWA/Desktop/QiuckEx-1/docs/smoke-scenarios.json)
- **Contract Package Mirror**: [`app/contract/contracts/quickex/smoke-scenarios.json`](file:///Users/NKWA/Desktop/QiuckEx-1/app/contract/contracts/quickex/smoke-scenarios.json)

Backend deployment tools, CI runners, and indexers consume this file directly without custom translation.

### JSON Schema

```json
{
  "version": "1.0.0",
  "contract": "quickex",
  "description": "Canonical post-deploy smoke scenarios covering core QuickEx contract entry points and validation rules.",
  "scenarios": [
    {
      "id": "SMOKE-001",
      "name": "health_check",
      "description": "Verify contract health check entry point returns true.",
      "category": "readiness",
      "entry_point": "health_check",
      "inputs": {},
      "expected_outcome": "success",
      "expected_result": true,
      "expected_error": null
    }
  ]
}
```

### Schema Field Specification

| Field | Type | Description |
|---|---|---|
| `id` | String | Unique scenario identifier (e.g. `SMOKE-001`). |
| `name` | String | Machine and human readable scenario title. |
| `description` | String | Clear summary of scenario intent and coverage. |
| `category` | String | Categorization band (`readiness`, `metadata`, `admin`, `commitment`, `escrow`, `dispute`, `privacy`). |
| `entry_point` | String | Target contract function name (e.g. `deposit`, `withdraw`, `refund`, `health_check`). |
| `inputs` | Object | Map of input parameter names and representative test values. |
| `expected_outcome` | String | Outcome requirement: `"success"` or `"rejection"`. |
| `expected_result` | Any / Null | Expected return value for success paths. |
| `expected_error` | Object / Null | Expected error object containing `name` and numeric `code` for rejection paths. |

---

## Canonical Scenario Catalog

| Scenario ID | Name | Category | Entry Point | Expected Outcome | Expected Error / Code |
|---|---|---|---|---|---|
| **SMOKE-001** | `health_check` | readiness | `health_check` | `success` | None (Returns `true`) |
| **SMOKE-002** | `get_deployment_metadata` | metadata | `get_deployment_metadata` | `success` | None (Returns active metadata) |
| **SMOKE-003** | `initialize_already_initialized` | admin | `initialize` | `rejection` | `AlreadyInitialized` (`201`) |
| **SMOKE-004** | `create_amount_commitment_success` | commitment | `create_amount_commitment` | `success` | None (Returns 32-byte hash) |
| **SMOKE-005** | `create_amount_commitment_invalid_amount` | commitment | `create_amount_commitment` | `rejection` | `InvalidAmount` (`100`) |
| **SMOKE-006** | `deposit_success` | escrow | `deposit` | `success` | None (Returns commitment hash) |
| **SMOKE-007** | `deposit_zero_amount` | escrow | `deposit` | `rejection` | `InvalidAmount` (`100`) |
| **SMOKE-008** | `deposit_duplicate_commitment` | escrow | `deposit` | `rejection` | `CommitmentAlreadyExists` (`303`) |
| **SMOKE-009** | `withdraw_success` | escrow | `withdraw` | `success` | None (Returns `true`) |
| **SMOKE-010** | `withdraw_already_spent` | escrow | `withdraw` | `rejection` | `AlreadySpent` (`304`) |
| **SMOKE-011** | `refund_not_expired` | escrow | `refund` | `rejection` | `EscrowNotExpired` (`308`) |
| **SMOKE-012** | `refund_success` | escrow | `refund` | `success` | None |
| **SMOKE-013** | `dispute_no_arbiter` | dispute | `dispute` | `rejection` | `NoArbiter` (`310`) |
| **SMOKE-014** | `resolve_dispute_not_arbiter` | dispute | `resolve_dispute` | `rejection` | `NotArbiter` (`312`) |
| **SMOKE-015** | `set_privacy_success` | privacy | `set_privacy` | `success` | None |
| **SMOKE-016** | `set_privacy_already_set` | privacy | `set_privacy` | `rejection` | `PrivacyAlreadySet` (`301`) |

---

## How to Run Smoke Scenarios Post-Testnet Deploy

### 1. Contract Unit Test Suite Execution

Run the Rust smoke test module against the Soroban test environment:

```bash
cd app/contract/contracts/quickex
cargo test smoke_test
```

This test suite embeds `smoke-scenarios.json`, executes each scenario programmatically, and asserts that contract outcomes match the exported spec.

### 2. Backend Automated Deployment Validation

To run smoke tests as part of backend post-deployment pipeline:

```bash
cd app/backend
npm run test:smoke:all
```

For remote testnet deployments:

```bash
SMOKE_TEST_BASE_URL=https://api-staging.quickex.io npm run test:smoke:all
```

### 3. Manual Verification via Soroban CLI

Execute specific scenarios on testnet using `stellar` / `soroban` CLI:

```bash
# Health check
stellar contract invoke \
  --id <CONTRACT_ID> \
  --source <SIGNER_KEY> \
  --network testnet \
  -- health_check

# Query deployment metadata
stellar contract invoke \
  --id <CONTRACT_ID> \
  --source <SIGNER_KEY> \
  --network testnet \
  -- get_deployment_metadata
```

---

## How to Update the Smoke Scenario Artifact

When contract behavior, new entry points, or validation rules change:

1. **Update `docs/smoke-scenarios.json`**:
   - Add new scenarios or update input/error specifications in `docs/smoke-scenarios.json`.
   - Sync changes to `app/contract/contracts/quickex/smoke-scenarios.json`.

2. **Update Test Assertions**:
   - Update tests in `app/contract/contracts/quickex/src/smoke_test.rs` to reflect modified scenario expectations.

3. **Verify Zero Behavior Drift**:
   - Run contract unit tests to verify all scenario assertions pass cleanly:
     ```bash
     cargo test smoke_test
     ```
   - Run backend smoke suite:
     ```bash
     cd app/backend && npm run test:smoke
     ```
