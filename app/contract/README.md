# QuickSilver Privacy Contract

Soroban smart contract implementing X-Ray privacy features for QuickEx.

## Overview

This contract provides the foundational privacy and escrow capabilities for the QuickEx platform. It enables:

- **Privacy Controls**: Selective visibility of on-chain activities
- **Escrow Services**: Secure holding of assets during transactions
- **Audit Trails**: Maintainable history of privacy state changes

## Prerequisites

- Rust 1.70 or higher
- Soroban CLI (`cargo install soroban-cli`)
- wasm32-unknown-unknown target (`rustup target add wasm32-unknown-unknown`)

## Building

```bash
# Navigate to the contract directory
cd app/contract

# Build the contract for release (optimized)
cargo build --target wasm32-unknown-unknown --release

# Build with debug logs enabled
cargo build --target wasm32-unknown-unknown --profile release-with-logs

# Build for development/testing
cargo build --target wasm32-unknown-unknown
```

## Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_enable_and_check_privacy

# Run tests with output
cargo test -- --nocapture

# Run tests with coverage (requires cargo-tarpaulin)
cargo tarpaulin --ignore-tests
```

## Quality Checks

```bash
# Check code formatting
cargo fmt --all -- --check

# Run clippy linter
cargo clippy --all-targets --all-features -- -D warnings

# Run all quality checks (fmt + clippy + test)
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test
```

## Deployment

### Local Network (for testing)

```bash
# Start local Soroban network
soroban dev

# Deploy contract to local network
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/qiuck_silver_contract.wasm \
  --source default

# Initialize contract (if needed)
soroban contract invoke \
  --id <CONTRACT_ID> \
  --source default \
  -- \
  health_check
```

### Testnet Deployment

```bash
# Deploy to testnet
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/qiuck_silver_contract.wasm \
  --source test \
  --network testnet

# Verify deployment
soroban contract invoke \
  --id <CONTRACT_ID> \
  --source test \
  --network testnet \
  -- \
  health_check
```

### Mainnet Deployment

```bash
# Deploy to mainnet (use with caution!)
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/qiuck_silver_contract.wasm \
  --source main \
  --network mainnet
```

## Development Workflow

1. Make changes to the contract code
2. Run quality checks: `cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings`
3. Run tests: `cargo test`
4. Build and test deployment locally: `soroban dev`
5. Create PR with changes

## Contract Interface

The contract exposes the following functions:

- `enable_privacy(account: Address, level: u32)` - Enable privacy for an account
- `privacy_status(account: Address)` - Get privacy status for an account
- `privacy_history(account: Address)` - Get privacy change history
- `create_escrow(from: Address, to: Address, amount: u64)` - Create escrow
- `health_check()` - Contract health check