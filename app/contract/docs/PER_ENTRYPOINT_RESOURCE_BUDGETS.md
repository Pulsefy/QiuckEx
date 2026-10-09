# Per-Entrypoint Resource Budget Assertions

> **Issue:** SC-W8-14 / Issue #875  
> **Target:** `QuickexContract` (Soroban smart contract)  
> **Status:** Active Quality Gate

---

## 1. Overview & Motivation

Earlier contract performance testing utilized aggregate benchmark gates. While aggregate metrics confirm total scenario throughput, they suffer from a critical flaw: **regressions in individual entrypoints can hide beneath overall headroom**. 

An entrypoint that quietly balloons in instruction or memory consumption might not trigger an aggregate ceiling in unit tests, but will fail with transaction-limit exhaustions when invoked on-chain by users.

This framework introduces **strict, per-entrypoint resource budget assertions** across all 93 public entrypoints of the `QuickexContract`.

---

## 2. Core Architecture

The system consists of three synchronized components:

1. **Baseline Specification (`entrypoint-budgets.json`)**:
   - Contains recorded CPU instruction and memory byte limits for every public entrypoint.
   - Documented tolerance: **10.0%** (`tolerance_pct: 10.0`), absorbing minor compiler or SDK variance while stopping genuine performance regressions.
   - Checked into version control for transparency and auditability.

2. **Test & Benchmark Assertion Suite (`src/entrypoint_budget_test.rs` & `src/bench_test.rs`)**:
   - Automatically measures each public entrypoint using Soroban's native `env.cost_estimate().budget()` metering.
   - Validates that every public entrypoint has a recorded budget.
   - Asserts that measured costs do not exceed `budget * (1 + tolerance_pct / 100)`.
   - On regression, formats an explicit diagnostic report detailing the entrypoint, resource type, measured value, budget, max allowed, and signed delta (`+/-`).

3. **CI/Regression Integration**:
   - Executed on `cargo test` and `cargo test bench_`.
   - Generates summary markdown artifacts (`quickex-entrypoint-budgets.md`) when `QUICKEX_BENCH_ARTIFACT_DIR` is set.

---

## 3. Acceptance Criteria Verification

| Acceptance Criterion | Implementation & Enforcement |
|----------------------|-----------------------------|
| **1. Recorded CPU & Memory Budget per Entrypoint** | All 93 public entrypoints on `QuickexContract` have explicit `cpu_budget` and `mem_budget` entries in `entrypoint-budgets.json`. `test_all_public_entrypoints_have_recorded_budgets` fails if any public entrypoint is omitted. |
| **2. Tests Fail Beyond Documented Tolerance** | `check_budget_limit` fails with an explicit error when `actual > budget * (1 + tolerance / 100)`. Default tolerance is documented at 10.0%. |
| **3. Explicit Reviewable Updates** | Tests never silently overwrite baseline files. Changing a budget requires an explicit git diff in `entrypoint-budgets.json` with commit review. |
| **4. Failure Report Names Entrypoint & Delta** | `BudgetAssertionFailure::format_report` outputs the exact entrypoint name, metric, actual cost, baseline budget, allowed ceiling, and absolute/percentage deltas. |

---

## 4. Failure Report Format

When an entrypoint exceeds its allowable threshold, the test produces a diagnostic report formatted as follows:

```text
================================================================================
PER-ENTRYPOINT RESOURCE BUDGET REGRESSION: 1 failure(s) detected
================================================================================
Entrypoint 'deposit' exceeded CPU instructions budget:
  actual:       480,000
  budget:       420,000
  tolerance:    10.00%
  max allowed:  462,000
  delta:        +60,000 (+14.29%)
  excess:       +18,000
--------------------------------------------------------------------------------
Budget changes require an explicit, reviewable update in `entrypoint-budgets.json`.
If this increase is intended, update the baseline with the rationale documented in the commit/PR.
```

---

## 5. Review & Update Workflow

If an intentional refactoring or feature addition causes a contract entrypoint to require more resources:

1. **Verify Necessity**: Ensure the instruction or memory increase cannot be optimized away (e.g., unnecessary storage accesses or redundant serialization).
2. **Update Baseline**: Update `app/contract/contracts/quickex/entrypoint-budgets.json` with the new target budget.
3. **Document in PR**:
   - Specify which entrypoint(s) increased.
   - Explain why the additional CPU or memory cost is necessary.
   - Reference the issue number and performance trade-offs.
4. **CI Validation**: Pull requests are gated on CI tests validating that all entrypoints pass against the committed baseline.

---

## 6. Running Budget Tests

From `app/contract`:

```sh
# Run all entrypoint budget assertion tests
cargo test entrypoint_budget_test

# Run specifically the per-entrypoint benchmark gate
cargo test bench_per_entrypoint_resource_budgets -- --nocapture

# Run the complete contract regression suite
cargo test
```
