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

### Detecting the version

- **v1 event**: `schema_version` key is absent from the data map.
- **v2+ event**: `schema_version` key is present; value equals the version number.

### Indexer migration plan (v1 → v2)

1. When processing an event, attempt to read `schema_version` from the data map.
2. If absent → decode with the v1 decoder (legacy path).
3. If present and `== 2` → decode with the v2 decoder.
4. If present and `> 2` → log a warning and skip until the indexer is updated.

The canonical version constant lives in `src/events.rs`:

```rust
pub const EVENT_SCHEMA_VERSION: u32 = 2;
```

Golden tests in `src/test.rs` (`golden_schema_v2` module) lock every topic and
payload key. Any schema drift will cause those tests to fail, preventing
accidental breakage.

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
  - Data: `schema_version`, `paused`, `timestamp`

- `AdminChanged`
  - Topics: `TOPIC_ADMIN`, `AdminChanged`, `old_admin`, `new_admin`
  - Data: `schema_version`, `timestamp`

- `ContractUpgraded`
  - Topics: `TOPIC_ADMIN`, `ContractUpgraded`, `new_wasm_hash`, `admin`
  - Data: `schema_version`, `timestamp`

- `ContractMigrated`
  - Topics: `TOPIC_ADMIN`, `ContractMigrated`, `admin`
  - Data: `schema_version`, `from_version`, `to_version`, `timestamp`

- `FeeConfigChanged`
  - Topics: `TOPIC_ADMIN`, `FeeConfigChanged`
  - Data: `schema_version`, `fee_bps`, `timestamp`

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
