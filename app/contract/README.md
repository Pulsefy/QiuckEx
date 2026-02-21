# QuickEx Privacy Contract

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
  --wasm target/wasm32-unknown-unknown/release/quickex.wasm \
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
  --wasm target/wasm32-unknown-unknown/release/quickex.wasm \
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
  --wasm target/wasm32-unknown-unknown/release/quickex.wasm \
  --source main \
  --network mainnet
```

## Development Workflow

1. Make changes to the contract code
2. Run quality checks: `cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings`
3. Run tests: `cargo test`
4. Build and test deployment locally: `soroban dev`
5. Create PR with changes

## Main Flows

### 1. Deployment & initialisation
1. Deploy the contract WASM.
2. Call `initialize(admin)` once to set the admin (required for pause, upgrade, admin transfer).

### 2. Deposit → Withdraw (escrow)
1. **Deposit**: Call `deposit(token, amount, owner, salt)` or `deposit_with_commitment(from, token, amount, commitment)`. The owner/from must authorize the token transfer.
2. Store the returned commitment (or the one you provided) securely; it is required to withdraw.
3. **Withdraw**: Call `withdraw(_token, amount, _commitment, to, salt)` with `to` as the recipient. The commitment is recomputed from `to`, `amount`, and `salt`; it must match an existing pending escrow. `to` must authorize.

### 3. Privacy
- **Boolean**: `set_privacy(owner, enabled)` and `get_privacy(owner)` for on/off privacy.
- **Level-based**: `enable_privacy(account, level)`, `privacy_status(account)`, `privacy_history(account)` for numeric levels.

### 4. Admin
- `set_paused(caller, new_state)` – pause/unpause (caller must be admin).
- `set_admin(caller, new_admin)` – transfer admin.
- `upgrade(caller, new_wasm_hash)` – upgrade contract (caller must authorize).

### 5. Read-only queries
- `get_commitment_state(commitment)` – escrow status (Pending/Spent/Expired).
- `verify_proof_view(amount, salt, owner)` – verify withdrawal params without submitting a tx.
- `get_escrow_details(commitment)` – full escrow entry.

---

## Contract Interface

The contract exposes the following functions:

### Storage Layout

The contract uses persistent storage with the following structure:

- `DataKey::Escrow(Bytes)` - Maps commitment hash to `EscrowEntry` containing token address, amount, owner, status, and creation timestamp
- `DataKey::EscrowCounter` - Tracks the number of escrows created
- `DataKey::Admin` - Stores the admin address
- `DataKey::Paused` - Stores the paused state of the contract
- `DataKey::PrivacyLevel(Address)` - Stores privacy level for each account
- `DataKey::PrivacyHistory(Address)` - Stores privacy history for each account

The `EscrowEntry` struct contains:
- `token: Address` - The token address
- `amount: i128` - The escrowed amount
- `owner: Address` - The owner of the escrow
- `status: EscrowStatus` - The status (Pending, Spent, Expired)
- `created_at: u64` - The ledger timestamp when created

Helper functions:
- `put_escrow(env: &Env, commitment: &Bytes, entry: &EscrowEntry)` - Store an escrow entry
- `get_escrow(env: &Env, commitment: &Bytes)` - Retrieve an escrow entry
- `has_escrow(env: &Env, commitment: &Bytes)` - Check if an escrow entry exists

### Privacy Management

- `enable_privacy(account: Address, level: u32)` - Enable privacy for an account
- `privacy_status(account: Address)` - Get privacy status for an account
- `privacy_history(account: Address)` - Get privacy change history

### Escrow

- `deposit(token: Address, amount: i128, owner: Address, salt: Bytes)` - Deposit funds and create an escrow entry
- `withdraw(to: Address, amount: i128, salt: Bytes)` - Withdraw funds by proving commitment ownership
- `create_escrow(from: Address, to: Address, amount: u64)` - Create escrow

### Amount Commitments (X-Ray Privacy Placeholder)

- `create_amount_commitment(owner: Address, amount: i128, salt: Bytes) -> Bytes` - Create a deterministic commitment hash
- `verify_amount_commitment(commitment: Bytes, owner: Address, amount: i128, salt: Bytes) -> bool` - Verify a commitment against claimed values

## Amount Commitments API

### Overview

The amount commitment functions provide a **placeholder** for X-Ray privacy shielded flows. These are deterministic SHA256-based commitments without real zero-knowledge guarantees. Future versions will integrate actual ZK proofs.

### Use Cases

- **Shielding transaction amounts** before full ZK integration
- **API shape validation** for frontend and backend clients
- **Audit trail commitments** to record hidden values without exposing them

### Serialization Format

Commitments are computed as `SHA256(owner_bytes || amount_bytes || salt_bytes)`:

| Component | Size | Format | Description |
|-----------|------|--------|-------------|
| Owner | Variable | XDR-serialized Address | Soroban address bytes |
| Amount | 16 bytes | Big-endian i128 | Transaction amount value |
| Salt | 0-256 bytes | Raw bytes | Randomness for uniqueness |

**Result**: 32-byte SHA256 hash

### API Examples

#### Create a Commitment

```rust
use soroban_sdk::{Address, Bytes, contract, contractimpl};

let owner = Address::from_string(&env, &"GXXXXX...");  // Owner's address
let amount = 1_500_000i128;                            // Amount in stroops
let salt = Bytes::from_slice(&env, &[42, 13, 99]);    // Random bytes

// Generate commitment
let commitment = client.create_amount_commitment(&owner, &amount, &salt);
// Result: 32-byte hash

// Store or transmit commitment (e.g., in transaction metadata)
```

#### Verify a Commitment

```rust
// Later, verify the commitment against claimed values
let is_valid = client.verify_amount_commitment(&commitment, &owner, &amount, &salt);

if is_valid {
    // Commitment matches; amount was not tampered with
    println!("Commitment verified!");
} else {
    // Mismatch: amount, salt, or owner was modified
    println!("Commitment invalid!");
}
```

#### Handling Tampering

```rust
// If any component is modified, verification fails
let wrong_amount = amount + 1;
assert!(!client.verify_amount_commitment(&commitment, &owner, &wrong_amount, &salt));

let modified_salt = Bytes::from_slice(&env, &[42, 13, 100]);
assert!(!client.verify_amount_commitment(&commitment, &owner, &amount, &modified_salt));

let other_owner = Address::generate(&env);
assert!(!client.verify_amount_commitment(&commitment, &other_owner, &amount, &salt));
```

### Constraints & Limitations

- **No confidentiality**: Commitments are deterministic hashes, not ZK proofs. Do not rely on them for privacy.
- **Maximum salt length**: 256 bytes to prevent resource exhaustion.
- **Non-negative amounts**: Negative amounts will panic; validate client-side.
- **Deterministic only**: Same inputs always produce identical commits; useful for audits but no hiding.
- **Not production-grade privacy**: Mark this feature as "experimental" in UX; full privacy requires ZK integration.

## View Functions (Read-Only RPC Calls)

### Check Commitment State
```bash
stellar contract invoke \
  --id <CONTRACT_ID> \
  --fn get_commitment_state \
  -- \
  --commitment <COMMITMENT_HASH>
```

### Verify Proof Before Withdrawal
```bash
stellar contract invoke \
  --id <CONTRACT_ID> \
  --fn verify_proof_view \
  -- \
  --amount 1000000 \
  --salt <SALT_BYTES> \
  --owner <ADDRESS>
```

### Get Full Escrow Details
```bash
soroban contract invoke \
  --id <CONTRACT_ID> \
  --fn get_escrow_details \
  -- \
  --commitment <COMMITMENT_HASH>
```


### Roadmap

1. **Current (v0.1)**: Deterministic SHA256 commitments
2. **Future (v0.2)**: Pedersen commitments with proper range proofs
3. **Target (v1.0)**: Full zero-knowledge privacy via Zether or Circom
````
