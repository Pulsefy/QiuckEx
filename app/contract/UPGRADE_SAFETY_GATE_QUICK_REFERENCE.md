# Upgrade Safety Gate – Quick Reference

**Issue #432** | Quick API reference for upgrade ceremonies

## API Summary

### 1. Set Upgrade Window (Admin)
```rust
set_upgrade_window(env, caller, start_epoch, end_epoch) -> Result<(), QuickexError>
```
- `start_epoch`: Ledger timestamp when upgrades allowed (0 = no window)
- `end_epoch`: Ledger timestamp when upgrades blocked (0 = no upper bound)
- **Error**: `InsufficientRole` if not admin

### 2. Get Upgrade Window
```rust
get_upgrade_window(env) -> (u64, u64)
```
- Returns `(start, end)` tuple

### 3. Start Upgrade (Admin) – **Window Gated**
```rust
start_upgrade(env, caller, new_version) -> Result<(), QuickexError>
```
- **Must be called during active window** (AC1)
- Sets `UpgradeInProgress = true`
- Emits: `UpgradeStarted { admin, old_version, new_version, ... }`
- **Errors**:
  - `InvalidAmount`: Window not active
  - `ContractPaused`: Already in-progress
  - `InsufficientRole`: Not admin

### 4. Update WASM
```rust
upgrade(env, caller, new_wasm_hash) -> Result<(), QuickexError>
```
- Swaps contract code (no storage changes)
- Emits: `ContractUpgraded { admin, new_wasm_hash, ... }`
- **Error**: `InsufficientRole` if not admin

### 5. Complete Upgrade (Admin)
```rust
complete_upgrade(env, caller, new_version) -> Result<u32, QuickexError>
```
- Calls `migrate()` + validates invariants (AC2)
- **Panics if invariants fail** → rolls back atomically
- Sets `UpgradeInProgress = false`
- Emits: `UpgradeCompleted { admin, old_version, new_version, ... }`
- **Returns**: New contract version
- **Errors**:
  - `InternalError`: Not in-progress, or invariants failed
  - `InvalidContractVersion`: Version mismatch

---

## Typical Ceremony (3-Step)

```
Day 1: Admin calls set_upgrade_window(1748606400, 1748610000)
       ↓
Day 2 @ 14:05: admin.start_upgrade(2u32)
       ↓ [UpgradeStarted emitted]
Day 2 @ 14:10: (Deploy) upload WASM, admin.upgrade(hash)
       ↓ [ContractUpgraded emitted]
Day 2 @ 14:15: admin.complete_upgrade(2u32)
       ↓ [Invariants checked, UpgradeCompleted emitted]
       ✓ Upgrade complete
```

---

## Error Codes (Repurposed)

| Error | Code | Meaning |
|-------|------|---------|
| `InvalidAmount` | 100 | Upgrade window not active |
| `ContractPaused` | 300 | Upgrade already in-progress |
| `InternalError` | 900 | Invariants failed post-upgrade |

---

## Storage Keys

| Key | Type | Purpose |
|-----|------|---------|
| `UpgradeWindowStart` | u64 | Epoch when upgrades allowed |
| `UpgradeWindowEnd` | u64 | Epoch when upgrades blocked |
| `UpgradeInProgress` | bool | Currently mid-upgrade? |

---

## Events (Indexer Filter)

### UpgradeStarted
```
topic[0] = "TOPIC_ADMIN"
topic[1] = "UpgradeStarted"
topic[2] = admin (address)

Data: {
  schema_version: u32,
  old_version: u32,
  new_version: u32,
  window_start: u64,
  window_end: u64,
  timestamp: u64
}
```

### UpgradeCompleted
```
topic[0] = "TOPIC_ADMIN"
topic[1] = "UpgradeCompleted"
topic[2] = admin (address)

Data: {
  schema_version: u32,
  old_version: u32,
  new_version: u32,
  timestamp: u64
}
```

---

## Invariants (Enforced at AC2)

Post-upgrade checks that **must** hold:

1. `fee_bps <= 10_000` (basis points)
2. `contract_version == CURRENT_CONTRACT_VERSION`
3. `admin != None`
4. Per-asset fees: `fee_bps <= 10_000`, `arbiter_bps <= 10_000`

**Violation**: Panic with `InternalError` (atomic rollback)

---

## Test Coverage

| Test | What | Lines |
|------|------|-------|
| `blocks_upgrade_outside_window` | AC1 window gating | 660–703 |
| `post_upgrade_invariants_enforced` | AC2 invariant checks | 705–737 |
| `emits_events` | AC3 event tracking | 739–770 |
| `blocks_double_start` | Safety: no concurrent upgrades | 772–798 |
| `non_admin_blocked` | Security: admin-only | 800–820 |

**Run**: `cargo test upgrade_safety_gate_`

---

## FAQ

**Q: Do I have to use `start_upgrade()` / `complete_upgrade()`?**  
A: No. The original `migrate()` still works standalone. These are optional extra guards.

**Q: Can I call `complete_upgrade()` without `start_upgrade()`?**  
A: No. `complete_upgrade()` checks `UpgradeInProgress` flag first → returns `InternalError`.

**Q: What if invariants fail during `complete_upgrade()`?**  
A: Contract panics → all storage changes rolled back → upgrade aborted. Retry after fixing.

**Q: Can I change the window during an upgrade?**  
A: Yes, but not recommended. Finish `complete_upgrade()` first for clarity.

**Q: How do indexers know if an upgrade succeeded?**  
A: Look for `UpgradeCompleted` event in the same transaction. No event = failure.

---

## Code Snippet: Full Ceremony

```rust
// Admin setup
let admin = Address::generate(&env);

// Step 1: Open window (e.g., next day, 1-hour duration)
let now = env.ledger().timestamp();
let start = now + 86_400u64;          // +1 day
let end = start + 3_600u64;           // +1 hour window
contract.set_upgrade_window(&admin, &start, &end)?;

// Time passes... now it's the scheduled time

// Step 2: Initiate upgrade
contract.start_upgrade(&admin, &2u32)?;
// → Event: UpgradeStarted { admin, 1, 2, start, end, now }

// Step 3a: Upload new WASM (external service)
let new_wasm_hash = /* SHA256 of new compiled WASM */;
contract.upgrade(&admin, &new_wasm_hash)?;
// → Event: ContractUpgraded { admin, wasm_hash, now }

// Step 3b: Finalize (run migration + check invariants)
let new_version = contract.complete_upgrade(&admin, &2u32)?;
// → Calls migrate() internally
// → Calls assert_post_upgrade_invariants()
// → If invariants fail: panic + rollback
// → If OK: Event: UpgradeCompleted { admin, 1, 2, now }
// → Returns: 2

assert_eq!(new_version, 2);
assert_eq!(contract.get_version(), 2);
```

---

## Related Documentation

- **UPGRADE_SAFETY_GATE.md**: Full spec, usage examples, checklist
- **IMPLEMENTATION_SUMMARY.md**: What was built, file changes, test matrix
- **upgrade_test.rs**: Test code and fixtures
- **storage.rs**: `assert_post_upgrade_invariants()` implementation
- **admin.rs**: `start_upgrade()`, `complete_upgrade()` implementation
- **events.rs**: Event definitions and publishers
- **lib.rs**: Public entrypoint signatures

---

**Version**: 1.0 | **Issue**: #432 | **Date**: May 29, 2026
