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

# Build the contract
cargo build --target wasm32-unknown-unknown --release

# Build with optimized settings
cargo build --target wasm32-unknown-unknown --profile release-with-logs