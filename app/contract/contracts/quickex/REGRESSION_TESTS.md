# QuickEx upgrade / regression test suite

This document describes the **regression test suite** used to future-proof QuickEx: after contract or SDK upgrades, these tests ensure existing escrows and commitments still behave correctly.

## Purpose

- **Re-run after upgrades** to confirm core flows are unchanged.
- **Baseline for future work** — all regression tests must pass before and after changes.
- **Easy to extend** when new features are added (see below).

## Golden path scenarios covered

| Scenario | Test(s) | Location |
|----------|--------|----------|
| Create escrows & commitments | `test_deposit`, `test_commitment_cycle`, `test_successful_withdrawal` | `src/test.rs` |
| Toggle privacy | `test_set_privacy_toggle_cycle_succeeds`, `test_set_and_get_privacy` | `src/test.rs` |
| Withdrawals | `test_successful_withdrawal` | `src/test.rs` |
| Refunds | `test_refund_successful` | `src/test.rs` |
| Full flow (single smoke test) | `regression_golden_path_full_flow` | `src/test.rs` |
| Commitment creation/verification | `test_create_and_verify_commitment_success` | `src/commitment_test.rs` |

## How to run the regression suite

From the **contract directory** (`app/contract/contracts/quickex/`):

```sh
# Run only the combined golden-path smoke test (fast)
cargo test regression_golden_path_full_flow

# Run all tests whose names start with "regression_"
cargo test regression_

# Run the full set of golden path tests by name
cargo test test_deposit test_successful_withdrawal test_refund_successful test_set_privacy_toggle_cycle_succeeds test_set_and_get_privacy test_commitment_cycle regression_golden_path_full_flow

# Run all contract tests (includes regression and others)
cargo test
```

From the **repository root**, using the workspace:

```sh
cargo test -p quickex
```

Snapshots are stored under `test_snapshots/`. If your environment generates or checks snapshots (e.g. via Soroban CLI), ensure they are updated only when behavior is intentionally changed.

## Where to add new regression cases

When you add a **new feature** that affects core escrow, commitment, or privacy behavior:

1. **Add one or more tests** in the appropriate module:
   - Main flows (deposit, withdraw, refund, privacy): `src/test.rs`
   - Commitment scheme only: `src/commitment_test.rs`
   - Storage invariants: `src/storage_test.rs`

2. **Mark regression tests** with a brief doc comment above the test:
   ```rust
   /// Regression suite: <short description of what this guards>.
   #[test]
   fn test_my_new_flow() { ... }
   ```

3. **Update this document** by adding the new test to the table under "Golden path scenarios covered" and, if relevant, to the `cargo test` command under "How to run the regression suite".

4. **Update the module doc** in `src/test.rs` if the new test is part of the golden path list there.

5. **Re-run the full suite** and fix any snapshot or assertion changes before merging.

## Acceptance criteria (for this suite)

- [x] Clearly-identified set of regression tests covering core flows.
- [x] Contributors know where to add new regression cases (this file + comments in code).
- [x] All tests pass and provide a baseline for future upgrade work.
