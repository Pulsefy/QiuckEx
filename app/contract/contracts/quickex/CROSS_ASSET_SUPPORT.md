# Cross-Asset Support Implementation

## Overview

This document describes how the QuickEx Soroban contract handles both Native XLM and Stellar Asset Contract (SAC) assets across all flows.

## Asset Types Supported

### 1. Native XLM
- **Description**: The native lumens of the Stellar network
- **Address**: Uses the Stellar network's native asset identifier
- **Decimals**: Typically 7 decimal places (1 XLM = 10,000,000 stroops)
- **Use Case**: Primary network token, low-fee transactions

### 2. Stellar Asset Contracts (SAC)
- **Description**: Tokens implemented via Stellar Asset Contracts
- **Examples**: USDC, custom tokens, wrapped assets
- **Decimals**: Varies by token (e.g., USDC uses 6 decimals)
- **Use Case**: Stablecoins, utility tokens, custom assets

## Implementation Details

### Standardized Token Interface

The contract uses Soroban's standardized `token::Client` interface which provides:

```rust
let token_client = token::Client::new(env, &token_address);
token_client.transfer(&from, &to, &amount);
```

This interface works uniformly across:
- Native XLM
- SAC tokens (USDC, custom tokens)
- Any future token types implementing the standard interface

### No Wrap/Unwrap Required

Unlike some blockchain systems, Soroban handles asset differences transparently:

1. **No Manual Wrapping**: Users don't need to wrap XLM before using it
2. **No Unwrapping**: Withdrawals return the same asset type as deposited
3. **Transparent Handling**: The contract treats all tokens identically

### Transfer Operations

All transfer operations use the same pattern regardless of asset type:

#### Deposit (Escrow Creation)
```rust
// Works for both XLM and SAC tokens
pub fn deposit(
    env: Env,
    token: Address,        // Token contract address
    amount: i128,          // Amount in base units
    owner: Address,
    salt: Bytes,
    timeout_secs: u64,
    arbiter: Option<Address>,
) -> Result<BytesN<32>, QuickexError>
```

#### Withdrawal
```rust
// Asset type preserved automatically
pub fn withdraw(
    env: Env,
    _token: &Address,      // Token address (reserved for future use)
    amount: i128,
    commitment: BytesN<32>,
    to: Address,
    salt: Bytes,
) -> Result<bool, QuickexError>
```

#### Refund
```rust
// Returns original asset type to owner
pub fn refund(
    env: Env,
    commitment: BytesN<32>,
    caller: Address,
) -> Result<(), QuickexError>
```

## Key Design Decisions

### 1. Generic Token Handling
**Decision**: Use a single generic token client for all asset types

**Rationale**:
- Soroban's token interface abstracts away asset-specific details
- Reduces code complexity and potential bugs
- Future-proof for new token types

### 2. No Special Cases for XLM
**Decision**: Treat XLM the same as any SAC token

**Rationale**:
- Simplifies implementation
- Consistent user experience
- No special-case logic to maintain

### 3. Asset Type Preservation
**Decision**: Deposited asset type is always returned in withdrawals/refunds

**Implementation**:
- Each escrow stores the token address
- All transfers use the stored token address
- No asset conversion or swapping

## Testing Strategy

### Test Coverage

The comprehensive test suite covers:

1. **Native XLM Tests**
   - Deposit and withdrawal with XLM
   - Refund flow with XLM
   - Multi-token scenarios including XLM

2. **SAC Token Tests**
   - USDC (6 decimals) deposit/withdrawal
   - Custom token deposit/refund
   - Large amount handling

3. **Cross-Asset Tests**
   - Multiple concurrent escrows with different tokens
   - Dispute resolution across token types
   - Privacy preservation across tokens

4. **Edge Cases**
   - Zero amount rejection
   - Large amount handling (overflow protection)
   - Token authorization requirements

### Running Tests

```bash
# Run all cross-asset tests
cargo test test_cross_asset

# Run specific test
cargo test test_cross_asset_native_xlm_deposit_withdrawal

# Run with output
cargo test test_cross_asset -- --nocapture
```

## Usage Examples

### Example 1: XLM Escrow

```rust
// User deposits 10 XLM into escrow
let xlm_address = /* Native XLM address */;
let amount = 10_000_000i128; // 10 XLM in stroops

contract.deposit(
    &xlm_address,
    &amount,
    &user,
    &salt,
    &3600, // 1 hour expiry
    &None,
);
```

### Example 2: USDC Escrow

```rust
// User deposits 100 USDC into escrow
let usdc_address = /* USDC SAC address */;
let amount = 100_000_000i128; // 100 USDC (6 decimals)

contract.deposit(
    &usdc_address,
    &amount,
    &user,
    &salt,
    &3600,
    &None,
);
```

### Example 3: Multi-Token Escrow

```rust
// Same user can create multiple escrows with different tokens
let xlm_commitment = contract.deposit(&xlm_address, &xlm_amount, &user, &salt1, &0, &None);
let usdc_commitment = contract.deposit(&usdc_address, &usdc_amount, &user, &salt2, &0, &None);
let custom_commitment = contract.deposit(&custom_address, &custom_amount, &user, &salt3, &0, &None);

// Each can be withdrawn independently
contract.withdraw(&xlm_address, &xlm_amount, &xlm_commitment, &user, &salt1);
contract.withdraw(&usdc_address, &usdc_amount, &usdc_commitment, &user, &salt2);
contract.withdraw(&custom_address, &custom_amount, &custom_commitment, &user, &salt3);
```

## Edge Cases Handled

### 1. Decimal Differences
- **Issue**: Different tokens use different decimal places
- **Solution**: Contract works with raw amounts; clients handle decimal conversion
- **Example**: 10 XLM = 10_000_000 stroops, 10 USDC = 10_000_000 (6 decimals)

### 2. Authorization
- **Issue**: Token transfers require user authorization
- **Solution**: Standard Soroban auth required for all deposits
- **Testing**: Verify auth requirements in test suite

### 3. Balance Verification
- **Issue**: Ensure correct token balances are transferred
- **Solution**: Each escrow tracks its token address; transfers use correct token client

### 4. No Overflow
- **Issue**: Large amounts could overflow
- **Solution**: Use i128 for amounts; tested with i128::MAX / 2

## Acceptance Criteria Met

✅ **Contract handles various asset types without edge-case failures**
- Tested with Native XLM, USDC, and custom tokens
- All flows work identically across asset types
- No special-case logic required

✅ **Standardized "wrap/unwrap" logic**
- Soroban handles this transparently
- No manual wrapping needed
- Asset type preserved automatically

✅ **Comprehensive cross-asset test suite**
- 10+ tests covering different scenarios
- Multi-token concurrent operations tested
- Edge cases covered (zero amounts, large amounts, privacy)

✅ **Address::transfer compatibility verified**
- All transfer calls use standardized token client
- Works uniformly across all asset types
- No asset-specific modifications needed

## Conclusion

The QuickEx contract successfully handles both Native XLM and SAC tokens through:

1. **Standardized Interface**: Using Soroban's token::Client
2. **Transparent Handling**: No manual wrap/unwrap logic
3. **Comprehensive Testing**: Full test coverage across asset types
4. **Future-Proof**: Works with any token implementing the standard interface

This design ensures reliability, simplicity, and extensibility for the QuickEx platform.
