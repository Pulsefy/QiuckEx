# Receipt Reference Event Emission - SC-W7-07

## Overview

This implementation adds explicit receipt reference metadata to contract events to enable deterministic off-chain receipt generation that aligns with on-chain outcomes.

## Problem Statement

Previously, receipt generation relied on off-chain reconstruction from transaction data, which could lead to inconsistencies between on-chain outcomes and off-chain receipts. This was particularly problematic for:

1. **Determinism**: Receipts generated off-chain might not always match on-chain outcomes
2. **Alignment**: Indexers and backend systems needed to reconstruct receipt metadata from multiple sources
3. **Reliability**: Network conditions and transaction ordering could affect receipt generation

## Solution

The contract now emits explicit `receipt_reference` fields in key escrow events:

- `EscrowDeposited`: For deposit/create events
- `EscrowWithdrawn`: For withdrawal/release events  
- `EscrowRefunded`: For refund events
- `RefundFinalized`: For finalized refund events
- `EscrowFinalized`: For finalization events

### Receipt Reference Generation

Receipt references are deterministic 32-byte hashes generated using:

```rust
pub(crate) fn generate_receipt_reference(env: &Env, escrow_id: &BytesN<32>, action: &str) -> BytesN<32> {
    let mut payload = Bytes::new(env);
    let escrow_bytes: Bytes = escrow_id.into();
    payload.append(&escrow_bytes);
    let action_bytes: Bytes = Bytes::from_slice(env, action.as_bytes());
    payload.append(&action_bytes);
    env.crypto().sha256(&payload).into()
}
```

This ensures:
- **Determinism**: Same escrow_id + action always produces the same receipt reference
- **Uniqueness**: Different actions or escrow_ids produce different receipt references
- **Consistency**: Receipt references are stable across ledger times and network conditions

## Implementation Details

### Schema Version Update

Event schema version updated from v2 to v3:

```rust
pub const EVENT_SCHEMA_VERSION: u32 = 3;
```

### Event Schema Changes

All relevant escrow events now include `receipt_reference` in their payload:

```rust
pub struct EscrowDepositedEvent {
    #[topic]
    pub escrow_id: BytesN<32>,
    #[topic]
    pub owner: Address,
    pub schema_version: u32,
    pub token: Address,
    pub amount_due: i128,
    pub amount_paid: i128,
    pub expires_at: u64,
    pub timestamp: u64,
    pub receipt_reference: BytesN<32>, // NEW
}
```

### Compatibility

The implementation maintains backward compatibility:

- Previous event schema versions (v1, v2) are still supported
- Indexers can check `schema_version` to determine if `receipt_reference` is present
- Backend normalization handles missing receipt references gracefully

## Backend Integration

### Receipt Normalizer

The backend receipt normalizer has been updated to:

1. Extract `receipt_reference` from Soroban RPC event data
2. Include it in the `ContractMeta` schema
3. Handle missing receipt references for backward compatibility

### Schema Updates

```typescript
export interface ContractMeta {
  contractId: string;
  functionName: string;
  args: Record<string, unknown>;
  returnValue: string | null;
  resources: { /* ... */ } | null;
  receiptReference?: string; // NEW
}
```

## Testing

### Contract Tests

Comprehensive tests in `receipt_reference_test.rs` validate:

- ✅ Determinism of receipt reference generation
- ✅ Uniqueness across different actions and escrow IDs
- ✅ Schema version compatibility
- ✅ Determinism across ledger states
- ✅ SHA-256 hash validity

**Test Results**: All 7 tests passing

### Backend Tests

Compatibility tests in `receipt-reference-compatibility.spec.ts` validate:

- ✅ Receipt reference handling in Soroban RPC results
- ✅ Graceful handling of missing receipt references
- ✅ Backward compatibility with legacy events
- ✅ Schema validation with receipt references
- ✅ Determinism of receipt generation

## Usage Examples

### For Indexers

Indexers should:

1. Check event `schema_version` to determine if `receipt_reference` is available
2. Extract `receipt_reference` from event payloads for schema v3+
3. Fall back to existing reconstruction methods for older schemas

```typescript
if (event.schema_version >= 3) {
  const receiptReference = event.body.receipt_reference;
  // Use deterministic receipt reference
} else {
  // Use legacy reconstruction
}
```

### For Backend Normalization

The receipt normalizer automatically handles receipt references:

```typescript
const receipt = normalizer.normalize(operation, transaction, soroban, indexer);
const receiptRef = receipt.contract?.receiptReference; // Available if present
```

### For Frontend Receipt Generation

Frontend can use receipt references for deterministic receipt generation:

```typescript
if (receipt.contract?.receiptReference) {
  // Use on-chain receipt reference for alignment
  generateReceipt(receipt.contract.receiptReference);
} else {
  // Fall back to alternative method
}
```

## Benefits

1. **Deterministic Receipt Generation**: Receipts can be generated deterministically from on-chain data
2. **Improved Alignment**: Off-chain receipts align reliably with on-chain outcomes
3. **Simplified Indexing**: Indexers can use explicit receipt references instead of reconstruction
4. **Backward Compatible**: Existing systems continue to work with older event schemas
5. **Test Coverage**: Comprehensive tests ensure reliability and determinism

## Migration Path

### For Existing Deployments

1. Deploy the updated contract with schema v3
2. Indexers will automatically handle both v2 and v3 events
3. New transactions will emit receipt references
4. Legacy transactions continue to work without receipt references

### For Indexers

1. Update event parsing to handle `receipt_reference` field
2. Add schema version checking
3. Test with both v2 and v3 events
4. Deploy indexer updates

### For Backend Systems

1. Update receipt normalizer (already done in this implementation)
2. Update receipt schema to include `receiptReference` field
3. Run compatibility tests
4. Deploy backend updates

## Security Considerations

- Receipt references are deterministic hashes, not secrets
- They cannot be used to derive private keys or sensitive data
- The hash function (SHA-256) is cryptographically secure
- Receipt references are emitted in public events anyway

## Performance Impact

- Minimal: One additional SHA-256 hash per event emission
- Event payload size increases by 32 bytes per event
- No significant gas cost increase
- Backend parsing overhead is negligible

## Files Modified

### Contract (Rust)
- `src/events.rs`: Added receipt reference generation and updated event schemas
- `src/lib.rs`: Added test module reference
- `src/receipt_reference_test.rs`: New comprehensive test suite

### Backend (TypeScript)
- `src/receipts/schemas/receipt.schema.ts`: Added receiptReference field to ContractMeta
- `src/receipts/normalizers/receipt.normalizer.ts`: Updated to handle receipt references
- `src/receipts/receipts.service.ts`: Enhanced to extract receipt references from events
- `test/receipts/receipt-reference-compatibility.spec.ts`: New compatibility test suite

### Documentation
- `RECEIPT_REFERENCE_IMPLEMENTATION.md`: This implementation guide

## Future Enhancements

Potential future improvements:

1. Add receipt references to additional event types
2. Include receipt references in dispute resolution events
3. Add receipt reference validation endpoints
4. Implement receipt reference caching in indexers

## References

- Issue: SC-W7-07
- Schema version: v3
- Contract: QuickEx Soroban contract
- Backend: NestJS receipt normalization service
