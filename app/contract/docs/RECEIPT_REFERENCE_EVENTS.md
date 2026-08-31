# Receipt Reference Events (SC-W7-07)

## Summary

Escrow lifecycle events now carry an explicit, deterministic
`receipt_reference` field so off-chain receipt generation can align with
on-chain outcomes reliably. The same escrow action always yields the same
reference, independent of ledger time, balances, or caller state.

## Derivation

```text
receipt_reference = SHA-256(
    escrow_id (32 bytes)
    || "QUICKEX::RECEIPT_REF::v1"
    || action_label
)
```

Implemented in `generate_receipt_reference` (`src/events.rs`). The domain tag
keeps receipt references distinct from the protocol's other SHA-256 digests
(escrow ids, amount commitments, stealth addresses).

Action labels are stable string constants:

| Constant | Value | Event |
|---|---|---|
| `RECEIPT_REF_ACTION_DEPOSIT` | `deposit` | `EscrowDeposited` |
| `RECEIPT_REF_ACTION_WITHDRAW` | `withdraw` | `EscrowWithdrawn` |
| `RECEIPT_REF_ACTION_FINALIZE` | `finalize` | `EscrowFinalized` |
| `RECEIPT_REF_ACTION_REFUND` | `refund` | `EscrowRefunded` |
| `RECEIPT_REF_ACTION_REFUND_FINALIZED` | `refund_finalized` | `RefundFinalized` |

## Invariants

1. **Determinism** – identical `escrow_id` + `action` always produce the same
   reference.
2. **Time independence** – ledger timestamps never participate in the hash.
3. **Domain separation** – different actions or escrows produce different
   references with negligible collision probability (SHA-256).
4. **Test-backed** – `receipt_reference_test.rs` locks all three invariants
   and asserts the emitted payload for every affected event.

## Schema versioning

Adding the field changes the event payload shape, so `EVENT_SCHEMA_VERSION`
was bumped from `2` to `3`:

- `src/events.rs` – `EVENT_SCHEMA_VERSION = 3`, `EVENT_SCHEMAS` payload keys
  updated, `EVENT_COMPATIBILITY` keeps v1/v2 in `compatible_versions`.
- `app/backend/src/ingestion/event-schema.ts` –
  `QUICKEX_EVENT_SCHEMA_VERSION = 3` and the escrow payload key catalog
  updated so ingestion knows about `receipt_reference`.
- `app/backend/src/ingestion/soroban-event.parser.ts` –
  `MAX_SUPPORTED_SCHEMA_VERSION = 3`; `receipt_reference` is decoded into the
  typed escrow events (null for v1/v2 payloads that lack the field).

## Backend receipt normalization compatibility

The normalizer (`app/backend/src/receipts/normalizers/receipt.normalizer.ts`)
accepts an optional `receiptReference` on `IndexerMetadata` and surfaces it on
the normalized receipt as `receiptReference: string | null`. Receipt
generation can therefore key on the on-chain reference whenever the indexer
has the contract event; payments and legacy events normalize to `null` and
remain fully backward compatible.
