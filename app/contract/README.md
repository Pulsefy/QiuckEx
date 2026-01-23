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

# Build with optimized settings
cargo build --target wasm32-unknown-unknown --profile release-with-logs
```

## Contract Interface

The contract exposes the following functions:

### Privacy Toggle (v0)
- `set_privacy(owner: Address, enabled: bool)` - Set privacy mode for owner (requires auth)
- `get_privacy(owner: Address)` - Get current privacy state for account

### Legacy Privacy Methods
- `enable_privacy(account: Address, level: u32)` - Enable privacy for an account *(deprecated)*
- `privacy_status(account: Address)` - Get privacy status for an account *(deprecated)*
- `privacy_history(account: Address)` - Get privacy change history

### Other Functions
- `create_escrow(from: Address, to: Address, amount: u64)` - Create escrow
- `health_check()` - Contract health check

## Privacy Toggle Usage

### Basic Usage
```rust
// Enable privacy for an account
contract.set_privacy(owner, true)?;

// Check privacy status
let is_private = contract.get_privacy(owner);
```

### Event Handling
The contract emits `PrivacyToggled` events when privacy state changes:
```rust
// Event structure
{
    owner: Address,      // Account that toggled privacy
    enabled: bool,       // New privacy state
    timestamp: u64       // When the change occurred
}
```

### Error Handling
The contract returns typed errors:
- `Unauthorized` - Access denied (non-owner trying to set privacy)
- `InvalidInput` - Invalid parameter provided
- `StorageError` - Storage operation failed
