# Upgrade Safety Gate & Post-Upgrade Invariants
**Issue #432** | Wave 5 – Lifecycle Management

## Overview

This document describes the contract-level safeguards and invariant enforcement mechanisms for safe, controlled upgrades in QuickEx.

### Key Features

1. **Explicit Upgrade Windows** – Upgrades only occur during admin-configured time windows
2. **Post-Upgrade Invariants** – Deterministic checks validate state after migration
3. **Upgrade Lifecycle Events** – `UpgradeStarted` and `UpgradeCompleted` for indexer tracking
4. **In-Progress Flag** – Prevents concurrent upgrade attempts
5. **Admin-Controlled Gating** – Only admins can set windows and control upgrades

---

## Storage Schema (Issue #432)

New storage keys added to `DataKey` enum:

| Key                      | Type | Purpose |
|--------------------------|------|---------|
| `UpgradeWindowStart`     | u64  | Ledger timestamp when upgrades become allowed |
| `UpgradeWindowEnd`       | u64  | Ledger timestamp when upgrades become blocked (0 = unbounded) |
| `UpgradeInProgress`      | bool | Flag: upgrade currently in-flight |

---

## Upgrade Workflow

### Step 1: Admin Sets Upgrade Window

```rust
set_upgrade_window(env, caller, start_epoch, end_epoch)
```

- **start_epoch**: Ledger timestamp when window opens (0 = reset/unset)
- **end_epoch**: Ledger timestamp when window closes (0 = no upper bound)
- **Requirements**: Caller must be admin; `end > start` if both non-zero

**Events**: None (internal state update)

**Example**: Allow upgrades between block 1000 and 2000

```rust
admin_account.set_upgrade_window(contract, 1000u64, 2000u64)?;
```

### Step 2: Admin Initiates Upgrade (Window Checks Here)

```rust
start_upgrade(env, caller, new_version)
```

- **new_version**: Target contract version after migration
- **Requirements**:
  - Caller must be admin
  - Current time must be within active window (AC1)
  - No upgrade already in-progress

**Checks** (AC1 – Acceptance Criterion):
- Window is set (`start != 0`)
- Current ledger timestamp ≥ `start`
- If `end != 0`: current ledger timestamp ≤ `end`
- Not already in-progress

**Events**: `UpgradeStarted {admin, old_version, new_version, window_start, window_end, timestamp}`

**Example**:

```rust
admin_account.start_upgrade(contract, 2u32)?;
// → UpgradeStarted event emitted
```

### Step 3: Update WASM

The caller (or deployment service) publishes new WASM and calls:

```rust
upgrade(env, caller, new_wasm_hash)
```

- **new_wasm_hash**: 32-byte SHA256 of new contract WASM
- **Requirements**: Caller must be admin

**Events**: `ContractUpgraded {admin, new_wasm_hash, timestamp}`

**Note**: This step does NOT perform storage migration; it only swaps the executable code.

### Step 4: Run Migration & Validate Invariants

```rust
complete_upgrade(env, caller, new_version)
```

- **new_version**: Expected target version (0 = auto-detect)
- **Requirements**:
  - Caller must be admin
  - `UpgradeInProgress` flag must be true
  - Must have called `start_upgrade` first

**Internal Flow**:
1. Call `migrate()` to run storage migrations
2. Validate post-upgrade invariants (AC2)
3. Clear `UpgradeInProgress` flag
4. Emit `UpgradeCompleted` event

**Events**: `UpgradeCompleted {admin, old_version, new_version, timestamp}`

**Example**:

```rust
admin_account.complete_upgrade(contract, 2u32)?;
// → UpgradeCompleted event emitted
// → Invariants checked; panics if violated
```

---

## Acceptance Criteria

### AC1: Upgrades Blocked Outside Window

**Test**: `upgrade_safety_gate_blocks_upgrade_outside_window`

- ✅ `start_upgrade()` fails when no window is set
- ✅ `start_upgrade()` fails before window start time
- ✅ `start_upgrade()` fails after window end time
- ✅ `start_upgrade()` succeeds within window `[start, end)`

**Error Code**: `InvalidAmount` (repurposed as "upgrade window not active")

### AC2: Post-Upgrade Invariants Enforced Deterministically

**Test**: `upgrade_safety_gate_post_upgrade_invariants_enforced`

Invariants checked in `storage::assert_post_upgrade_invariants()`:

1. **Fee Bounds**: `fee_bps ≤ 10_000` basis points
2. **Version Set**: `contract_version == CURRENT_CONTRACT_VERSION`
3. **Admin Initialized**: `admin != None`
4. **Escrow Counter Valid**: u64 (always valid, implicit)
5. **Per-Asset Fees**: Validated at write time (bounds: `fee_bps ≤ 10_000`, `arbiter_bps ≤ 10_000`)

**Violation Behavior**: Panic with `InternalError` deterministically

**Example Violation**:
- If a corrupted migration sets `fee_bps = 20_000`, `complete_upgrade()` panics
- Indexers/monitors can detect via transaction failure logs

### AC3: Indexers Track Upgrades via Events

**Test**: `upgrade_safety_gate_emits_events`

Events emitted in strict sequence:

```
UpgradeStarted {
  admin,
  old_version,
  new_version,
  window_start,
  window_end,
  timestamp,
  schema_version = 2
}

ContractUpgraded {
  admin,
  new_wasm_hash,
  timestamp,
  schema_version = 2
}

[Migration storage changes]

UpgradeCompleted {
  admin,
  old_version,
  new_version,
  timestamp,
  schema_version = 2
}
```

**Indexer Use**:
- Filter by topic `"TOPIC_ADMIN"` and type `"UpgradeStarted"` / `"UpgradeCompleted"`
- Group by `(admin, old_version, new_version, timestamp)` tuples
- Track deployment timeline and version history

---

## Event Details

### UpgradeStarted

```rust
#[contractevent(topics = ["TOPIC_ADMIN", "UpgradeStarted"])]
pub struct UpgradeStartedEvent {
    #[topic]
    pub admin: Address,
    
    pub schema_version: u32,           // = 2
    pub old_version: u32,               // Current contract version
    pub new_version: u32,               // Target version
    pub window_start: u64,              // Ledger timestamp (start of window)
    pub window_end: u64,                // Ledger timestamp (end, 0 = unbounded)
    pub timestamp: u64,                 // Ledger timestamp (now)
}
```

### UpgradeCompleted

```rust
#[contractevent(topics = ["TOPIC_ADMIN", "UpgradeCompleted"])]
pub struct UpgradeCompletedEvent {
    #[topic]
    pub admin: Address,
    
    pub schema_version: u32,           // = 2
    pub old_version: u32,               // Version before migration
    pub new_version: u32,               // Version after migration
    pub timestamp: u64,                 // Ledger timestamp (now)
}
```

---

## Error Codes

New or repurposed errors:

| Error | Code | Trigger | Context |
|-------|------|---------|---------|
| `InvalidAmount` | 100 | Upgrade window not active | `start_upgrade()` outside `[start, end)` |
| `ContractPaused` | 300 | Upgrade already in progress | `start_upgrade()` called twice |
| `InternalError` | 900 | Post-upgrade invariants failed | `complete_upgrade()` after failed migration |

---

## Usage Example

### Planned Upgrade Scenario

**Day 1, 13:00 UTC**: Admin schedules an upgrade window for Day 2, 14:00–15:00 UTC

```rust
let block_timestamp = env.ledger().timestamp(); // e.g., 1748520000 (May 30, 2025 @ 13:00)
let start = block_timestamp + 86_400u64;         // +1 day = 1748606400
let end = start + 3_600u64;                      // +1 hour window

admin.set_upgrade_window(contract, start, end)?;
// No events yet; state updated silently
```

**Day 2, 14:05 UTC**: Admin initiates upgrade during window

```rust
admin.start_upgrade(contract, 2u32)?;
// → Emits UpgradeStarted { admin, 1, 2, 1748606400, 1748610000, 1748610300 }
```

**Day 2, 14:10 UTC**: WASM uploaded; deploy swap

```rust
admin.upgrade(contract, new_wasm_hash)?;
// → Emits ContractUpgraded { admin, new_wasm_hash, 1748610600 }
```

**Day 2, 14:15 UTC**: Run migration & invariant checks

```rust
let new_version = admin.complete_upgrade(contract, 2u32)?;
// Internally:
//   1. Calls migrate() → runs v0→v1 logic
//   2. Calls assert_post_upgrade_invariants() → checks fee_bps, version, admin, etc.
//   3. Clears UpgradeInProgress flag
//   4. Emits UpgradeCompleted { admin, 1, 2, 1748610900 }
// Returns: 2
```

### Blocked Upgrade (Outside Window)

```rust
// Same setup as above; but now it's Day 1, 13:00 UTC (before window)
admin.start_upgrade(contract, 2u32)?;
// → Err: InvalidAmount ("upgrade window not active")
```

---

## Testing

### Unit Tests (in `upgrade_test.rs`)

Run all upgrade safety tests:

```bash
cargo test upgrade_safety_gate_ -- --nocapture
```

Tests included:

1. **`upgrade_safety_gate_blocks_upgrade_outside_window`**
   - Verifies AC1: blocks before/after window

2. **`upgrade_safety_gate_post_upgrade_invariants_enforced`**
   - Verifies AC2: invariant validation succeeds on clean upgrade

3. **`upgrade_safety_gate_emits_events`**
   - Verifies AC3: events emitted in correct sequence

4. **`upgrade_safety_gate_blocks_double_start`**
   - Ensures `UpgradeInProgress` flag prevents concurrent upgrades

5. **`upgrade_safety_gate_non_admin_blocked`**
   - Verifies only admins can gate/start upgrades

### Integration Tests

When deployed on-chain:

1. Set window during off-peak hours
2. Trigger via testnet admin account
3. Monitor event logs via Stellar event stream
4. Verify invariants by querying contract state post-upgrade
5. Check no stale escrows in `Pending` state from old code

---

## Migration Checklist

When upgrading between contract versions:

- [ ] Generate new WASM hash: `soroban contract build` → SHA256
- [ ] Admin calls `set_upgrade_window(start, end)` during maintenance window
- [ ] Admin calls `start_upgrade(new_version)`
- [ ] Deployment service uploads WASM
- [ ] Admin calls `upgrade(wasm_hash)`
- [ ] Admin calls `complete_upgrade(new_version)`
- [ ] Monitor `UpgradeCompleted` event
- [ ] Query contract version: `get_version()` should match `new_version`
- [ ] Run smoke tests: `deposit`, `withdraw`, `set_privacy` (regression suite)
- [ ] Verify no transaction failures post-upgrade (invariant panic)

---

## FAQ

**Q: Can I call `migrate()` without `start_upgrade()`?**
A: Yes. `migrate()` is standalone and always allowed. `start_upgrade()` / `complete_upgrade()` add extra gating for safety but are optional for ad-hoc migrations.

**Q: What if I miss the upgrade window?**
A: Call `set_upgrade_window()` again to open a new one. There's no "missed upgrade" penalty; you just reschedule.

**Q: Can the window be changed mid-upgrade?**
A: Yes, but not recommended. Changing `start` / `end` while `UpgradeInProgress` is true could cause confusion. Ensure `complete_upgrade()` finishes first.

**Q: What happens if invariants fail?**
A: `complete_upgrade()` panics with `InternalError`. The contract state is rolled back (no partial writes), and the upgrade is effectively aborted. Retry after fixing the migration logic.

**Q: How do indexers detect a failed upgrade?**
A: Look for `UpgradeStarted` events without a corresponding `UpgradeCompleted` in the same ledger sequence, or for transaction failures (ledger meta) between start/end timestamps.

---

## Related Issues

- **#310**: Upgrade simulation test harness (foundational)
- **#432**: Upgrade safety gate + invariants (this issue)
- **#157**: Privacy v2 (uses similar event patterns)
- **#305**: Fee Router v2 (affected by fee invariant bounds)

---

## References

- [Soroban Contract Upgrade Guide](https://developers.stellar.org/build/guides/soroban-migration)
- [QuickEx Invariant Checks](./UPGRADE_SAFETY_GATE.md) (this file)
- [`storage.rs::assert_post_upgrade_invariants()`](../contracts/quickex/src/storage.rs)
- [`admin.rs::start_upgrade()`, `complete_upgrade()`](../contracts/quickex/src/admin.rs)
