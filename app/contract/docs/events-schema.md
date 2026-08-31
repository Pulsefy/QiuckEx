# QuickEx Contract Events Schema

This document defines the indexer-facing contract event schema for `quickex`.

## Design goals

- Stable topic names for long-lived integrations.
- Minimal but expressive payload fields.
- Consistent payload shape and topic ordering.
- Clear domain separation: `Escrow*`, `Admin*`, `Privacy*`, `Stealth*`.
- Explicit schema versioning so indexers can evolve safely across contract upgrades.

## Schema versioning

Every event payload includes a `schema_version: u32` field (introduced in v2).
Indexers MUST read this field before decoding any other payload field.

| Version | Description                                      |
|---------|--------------------------------------------------|
| 1       | Original schema – no `schema_version` field      |
| 2       | Added `schema_version` to every event payload    |
| 3       | Added deterministic `receipt_reference` to escrow lifecycle events (SC-W7-07) |

### Detecting the version

- **v1 event**: `schema_version` key is absent from the data map.
- **v2+ event**: `schema_version` key is present; value equals the version number.

### Indexer migration plan (v1 → v3)

1. When processing an event, attempt to read `schema_version` from the data map.
2. If absent → decode with the v1 decoder (legacy path).
3. If present and `== 2` → decode with the v2 decoder.
4. If present and `== 3` → decode with the v3 decoder.
5. If present and `> 3` → log a warning and skip until the indexer is updated.
   The reference implementation lives in
   `app/backend/src/ingestion/soroban-event.parser.ts`.

### Versioning policy — when the version MUST be incremented

Bump `EVENT_SCHEMA_VERSION` in `src/events.rs` whenever ANY of the following
changes land on any emitted event:

| Change                                                        | Bump? |
|---------------------------------------------------------------|-------|
| Field added to or removed from any event payload              | YES   |
| Field renamed (rename = remove + add)                         | YES   |
| Field type or encoding changes (e.g. `u64` → `u128`)          | YES   |
| Semantic meaning of an existing field changes                 | YES   |
| Topic layout changes (namespace, event symbol, indexed order) | YES   |
| New event type introduced                                     | NO*   |
| Bug fix that does not alter payload/topic shape               | NO    |

\* A new event type does not bump the version because existing decoders ignore
unknown event names, but the new type MUST be registered in `EVENT_SCHEMAS`
(`src/events.rs`), in the backend `QUICKEX_EVENT_SCHEMA_CONTRACTS`
(`app/backend/src/ingestion/event-schema.ts`), and in the catalogue below.

Rationale: indexers replay history across contract upgrades. Skipping a
required bump silently corrupts historical replay; an unnecessary bump only
costs indexers one extra decoder branch. When in doubt, bump.

Release procedure:

1. Increment `EVENT_SCHEMA_VERSION` in `src/events.rs`.
2. Add the old version to `compatible_versions` for every affected event in
   `EVENT_SCHEMAS` / `EVENT_COMPATIBILITY`, and mirror the change in the
   backend `event-schema.ts`.
3. Add a row to the version table above describing the change.
4. Deploy indexer support for the new version BEFORE promoting the upgraded
   contract; only then raise `MAX_SUPPORTED_SCHEMA_VERSION`
   (`app/backend/src/ingestion/soroban-event.parser.ts`).
5. Keep `test_event_schema_catalog_locks_canonical_topics_and_payloads`
   green: its length assertion must equal the number of emitted event types,
   guaranteeing every emitted event is version-checked.

The canonical version constant lives in `src/events.rs`:

```rust
pub const EVENT_SCHEMA_VERSION: u32 = 3;
```

Golden tests in `src/test.rs` (`test_event_schema_catalog_*`,
`test_event_snapshot_*`) lock every topic and payload key. Any schema drift
will cause those tests to fail, preventing accidental breakage.

---

## Naming convention

- Event names use `PascalCase` topics.
- Event structs use `<Topic>NameEvent` in code.
- All events include `schema_version` and `timestamp` in the data payload.

## Topic and payload rules

1. **Escrow lifecycle events**
   - Topic[0] = `"TOPIC_ESCROW"`
   - Topic[1] = event name
   - Topic[2] = `escrow_id` (BytesN<32>)
   - Topic[3] = `owner` or `arbiter` (Address)
   - Data = `schema_version`, domain-specific fields, `timestamp`

2. **Admin action events**
   - Topic[0] = `"TOPIC_ADMIN"`
   - Topic[1] = event name
   - Topics include admin identity fields relevant to the action
   - Data = `schema_version`, action state, `timestamp`

3. **Privacy events**
   - Topic[0] = `"TOPIC_PRIVACY"`
   - Topic[1] = event name
   - Topic[2] = `owner` (Address)
   - Data = `schema_version`, state change, `timestamp`

4. **Stealth events**
   - Topic[0] = `"TOPIC_STEALTH"`
   - Topic[1] = event name
   - Topic[2] = `stealth_address` (BytesN<32>)
   - Topic[3] = `eph_pub` or `recipient`
   - Data = `schema_version`, domain-specific fields, `timestamp`

## Receipt references (v3)

Since schema v3, escrow lifecycle events carry a deterministic
`receipt_reference: BytesN<32>` payload field so off-chain receipt generation
can align with on-chain outcomes reliably. See
[`RECEIPT_REFERENCE_EVENTS.md`](./RECEIPT_REFERENCE_EVENTS.md) for the full
design, derivation, and backend compatibility notes.

Affected events:

- `EscrowDeposited` (create)
- `EscrowWithdrawn` (release)
- `EscrowFinalized` (release)
- `EscrowRefunded` (refund)
- `RefundFinalized` (refund)

---

## Current event catalogue (Schema v2)

### Privacy

- `PrivacyToggled`
  - Topics: `TOPIC_PRIVACY`, `PrivacyToggled`, `owner`
  - Data: `schema_version`, `enabled`, `timestamp`

### Escrow

- `EscrowDeposited`
  - Topics: `TOPIC_ESCROW`, `EscrowDeposited`, `escrow_id`, `owner`
  - Data: `schema_version`, `token`, `amount`, `expires_at`, `timestamp`

- `EscrowWithdrawn`
  - Topics: `TOPIC_ESCROW`, `EscrowWithdrawn`, `escrow_id`, `owner`
  - Data: `schema_version`, `token`, `amount`, `fee`, `timestamp`

- `EscrowRefunded`
  - Topics: `TOPIC_ESCROW`, `EscrowRefunded`, `escrow_id`, `owner`
  - Data: `schema_version`, `token`, `amount`, `timestamp`

- `EscrowDisputed`
  - Topics: `TOPIC_ESCROW`, `EscrowDisputed`, `escrow_id`, `arbiter`
  - Data: `schema_version`, `timestamp`

### Admin

- `ContractPaused`
  - Topics: `TOPIC_ADMIN`, `ContractPaused`, `admin`
  - Data: `schema_version`, `paused`, `reason`, `timestamp`

- `PauseFlagsChanged`
  - Topics: `TOPIC_ADMIN`, `PauseFlagsChanged`, `admin`
  - Data: `schema_version`, `enabled`, `disabled`, `flags`, `reason`, `timestamp`

- `EmergencyModeActivated`
  - Topics: `TOPIC_ADMIN`, `EmergencyModeActivated`, `admin`
  - Data: `schema_version`, `timestamp`

- `AdminChanged`
  - Topics: `TOPIC_ADMIN`, `AdminChanged`, `old_admin`, `new_admin`
  - Data: `schema_version`, `timestamp`

- `ContractUpgraded`
  - Topics: `TOPIC_ADMIN`, `ContractUpgraded`, `new_wasm_hash`, `admin`
  - Data: `schema_version`, `timestamp`

- `ContractMigrated`
  - Topics: `TOPIC_ADMIN`, `ContractMigrated`, `admin`
  - Data: `schema_version`, `from_version`, `to_version`, `timestamp`

- `UpgradeStarted`
  - Topics: `TOPIC_ADMIN`, `UpgradeStarted`, `admin`
  - Data: `schema_version`, `old_version`, `new_version`, `window_start`,
    `window_end`, `timestamp`

- `UpgradeCompleted`
  - Topics: `TOPIC_ADMIN`, `UpgradeCompleted`, `admin`
  - Data: `schema_version`, `old_version`, `new_version`, `timestamp`

- `FeeConfigChanged`
  - Topics: `TOPIC_ADMIN`, `FeeConfigChanged`
  - Data: `schema_version`, `old_fee_bps`, `fee_bps`, `timestamp`

- `PlatformWalletChanged`
  - Topics: `TOPIC_ADMIN`, `PlatformWalletChanged`, `wallet`
  - Data: `schema_version`, `timestamp`

### Stealth

- `EphemeralKeyRegistered`
  - Topics: `TOPIC_STEALTH`, `EphemeralKeyRegistered`, `stealth_address`, `eph_pub`
  - Data: `schema_version`, `token`, `amount`, `expires_at`, `timestamp`

- `StealthWithdrawn`
  - Topics: `TOPIC_STEALTH`, `StealthWithdrawn`, `stealth_address`, `recipient`
  - Data: `schema_version`, `token`, `amount`, `timestamp`
