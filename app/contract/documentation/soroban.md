# Soroban Contract Developer Guide

This document is the single source of truth for building, testing, and deploying the QuickEx Soroban contract.

## Prerequisites

Install the following before you start:

- Rust 1.70+
- `soroban-cli`
- WASM target for Rust (`wasm32-unknown-unknown`)

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add WASM build target
rustup target add wasm32-unknown-unknown

# Install Soroban CLI
cargo install soroban-cli
```

Verify tools:

```bash
rustc --version
cargo --version
soroban --version
```

## Setup

From the repository root:

```bash
cd app/contract
```

(Optional, recommended) use Rust stable:

```bash
rustup default stable
```

## Build

Use standard build commands below.

```bash
# Debug build
cargo build

# Release build for Soroban WASM
cargo build --target wasm32-unknown-unknown --release

# Alternative profile used in this repo
cargo build --target wasm32-unknown-unknown --profile release-with-logs
```

Expected contract artifact path:

```text
target/wasm32-unknown-unknown/release/quickex.wasm
```

## Test

Run all tests:

```bash
cargo test
```

Run a specific test:

```bash
cargo test test_enable_and_check_privacy
```

Run tests with output:

```bash
cargo test -- --nocapture
```

## Required Verification Evidence

To confirm the documented setup works, contributors **must attach a screenshot** of a successful test run in their PR.

Minimum acceptable evidence:

- Terminal screenshot showing command: `cargo test`
- Output indicating tests passed (e.g. `test result: ok`)
- Timestamp visible in terminal/shell prompt if possible

## Deployment

Before any testnet or mainnet release, complete the checklist in [deployment-checklist.md](deployment-checklist.md).

### 1) Local network deployment

```bash
# In one terminal: start local Soroban network
soroban dev
```

In another terminal:

```bash
cd app/contract

soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/quickex.wasm \
  --source default
```

Optionally verify with a read/invoke call:

```bash
soroban contract invoke \
  --id <CONTRACT_ID> \
  --source default \
  -- \
  health_check
```

### 2) Testnet deployment

Use the same release artifact and operator order that passed the deployment checklist.

```bash
cd app/contract

soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/quickex.wasm \
  --source test \
  --network testnet
```

Verify:

```bash
soroban contract invoke \
  --id <CONTRACT_ID> \
  --source test \
  --network testnet \
  -- \
  health_check
```

Recommended post-deploy validation:

1. Call `get_deployment_metadata` and confirm the returned contract ID, schema version, and wasm hash are correct.
2. Run one known event-emitting action and confirm the event payload still matches [docs/events-schema.md](../docs/events-schema.md).
3. Record the contract ID and network in the PR.

### 3) Mainnet deployment

Mainnet deployment must repeat the validated testnet flow with the mainnet source key and network.

```bash
cd app/contract

soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/quickex.wasm \
  --source main \
  --network mainnet
```

> Caution: Mainnet deployment is irreversible and should only be done after review and testnet validation.

## Deployment gates

The following checks are required before a deploy PR can be merged:

- [ ] Benchmarks are green: `cargo test bench_ -- --nocapture`
- [ ] Upgrade harness is green: `cargo test upgrade_harness_ -- --nocapture`
- [ ] Event schema is locked: `cargo test test_event_schema_catalog_locks_canonical_topics_and_payloads`
- [ ] Governance settings are documented: threshold keys and pause policy
- [ ] Post-deploy validation is defined: metadata view and event smoke test

## Recommended local quality checks

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Or in one line:

```bash
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test
```

## Troubleshooting

- `target not found: wasm32-unknown-unknown`
  - Run: `rustup target add wasm32-unknown-unknown`
- `soroban: command not found`
  - Ensure `cargo install soroban-cli` completed and `$HOME/.cargo/bin` is on `PATH`
- Failing tests after dependency changes
  - Run `cargo clean && cargo test`

## Pull Request checklist (for this doc)

- [ ] `app/contract/documentation/soroban.md` exists
- [ ] Steps for Prerequisites, Setup, Build, Test, Deploy are present and ordered
- [ ] Markdown formatting is clean and readable
- [ ] PR includes screenshot of successful `cargo test`
- [ ] Deploy checklist is linked and used for release-related changes
