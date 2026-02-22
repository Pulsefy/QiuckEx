# Test snapshots

This directory holds **ledger/auth snapshots** produced when running the QuickEx contract tests (e.g. via `cargo test` or Soroban test tooling). Layout mirrors the test modules:

- **test/** — snapshots for `src/test.rs` (escrow, privacy, withdraw, refund, upgrade)
- **commitment_test/** — snapshots for `src/commitment_test.rs`
- **storage_test/** — snapshots for `src/storage_test.rs`

These snapshots are part of the **upgrade/regression suite**: after contract or SDK upgrades, re-run tests and ensure snapshots still match (or are intentionally updated). See **../REGRESSION_TESTS.md** for how to run the regression suite and add new cases.

**Do not edit snapshot JSON by hand** unless you are intentionally changing expected behavior; prefer fixing the contract or test logic.
