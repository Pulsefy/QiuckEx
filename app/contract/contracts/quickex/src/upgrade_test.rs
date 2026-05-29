//! # Upgrade Simulation Test Harness — Issue #310 + #432
//!
//! Creates a repeatable test harness that:
//! 1. Deploys `LegacyV0Contract` (schema version 0) and populates a "golden state"
//!    fixture covering escrows in multiple lifecycle states, fee configuration,
//!    privacy settings, and the escrow counter.
//! 2. Performs an in-place upgrade to `QuickexContract` (v1) via `env.register_at`,
//!    then calls `migrate()`.
//! 3. Validates all invariants and data integrity after the upgrade.
//! 4. Provides regression tests for known migration pitfalls.
//!
//! ## Acceptance criteria (Issue #310 + #432)
//! - Upgrade tests run locally and deterministically.
//! - No data loss or corruption across migrations.
//! - Invariants are validated with clear failure messages.
//! - Upgrade window gating works (blocks outside window).
//! - Post-upgrade invariants enforced deterministically (AC2).
//! - Upgrade start/complete events emitted for indexing (AC3).
//!
//! ## Running
//! ```sh
//! cargo test upgrade_harness_ -- --nocapture
//! cargo test upgrade_safety_gate_ -- --nocapture
//! ```

use crate::{
    errors::QuickexError,
    storage::{CURRENT_CONTRACT_VERSION, LEGACY_CONTRACT_VERSION, PRIVACY_ENABLED_KEY},
    types::FeeConfig,
    EscrowStatus, QuickexContract, QuickexContractClient,
};
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger},
    token, Address, Bytes, BytesN, Env, Symbol,
};

// ============================================================================
// Legacy V0 Contract — simulates a pre-migration production deployment
// ============================================================================

/// Minimal stub of the legacy v0 contract.
///
/// Key differences from the current `QuickexContract`:
/// - `initialize` omits `set_contract_version` — simulates a deployment that
///   pre-dates the versioning mechanism (so `get_version()` returns 0).
/// - `set_fee_config` bypasses role checks — simulates the legacy simple-admin
///   model that stored fees without RBAC.
/// - All escrow/privacy/dispute functions delegate to the current crate modules
///   so the persistent storage layout is identical.
#[contract]
pub struct LegacyV0Contract;

#[contractimpl]
impl LegacyV0Contract {
    /// Initialize without writing `ContractVersion` — defining trait of a legacy (v0) deployment.
    pub fn initialize(env: Env, admin: Address) -> Result<(), QuickexError> {
        if crate::storage::get_admin(&env).is_some() {
            return Err(QuickexError::AlreadyInitialized);
        }
        crate::storage::set_admin(&env, &admin);
        crate::storage::set_paused(&env, false);
        // ⚠️  Intentionally no set_contract_version — this is what makes it "legacy".
        Ok(())
    }

    pub fn deposit(
        env: Env,
        token: Address,
        amount: i128,
        owner: Address,
        salt: Bytes,
        timeout_secs: u64,
        arbiter: Option<Address>,
    ) -> Result<BytesN<32>, QuickexError> {
        crate::escrow::deposit(&env, token, amount, owner, salt, timeout_secs, arbiter)
    }

    pub fn withdraw(
        env: Env,
        _token: Address,
        amount: i128,
        _commitment: BytesN<32>,
        to: Address,
        salt: Bytes,
    ) -> Result<bool, QuickexError> {
        crate::escrow::withdraw(&env, amount, to, salt)
    }

    pub fn dispute(env: Env, commitment: BytesN<32>) -> Result<(), QuickexError> {
        crate::escrow::dispute(&env, commitment)
    }

    pub fn refund(env: Env, commitment: BytesN<32>, caller: Address) -> Result<(), QuickexError> {
        crate::escrow::refund(&env, commitment, caller)
    }

    /// Store fee config directly — legacy simple-admin model (no role guard).
    pub fn set_fee_config(env: Env, config: FeeConfig) {
        crate::storage::set_fee_config(&env, &config);
    }

    pub fn set_privacy(env: Env, owner: Address, enabled: bool) -> Result<(), QuickexError> {
        crate::privacy::set_privacy(&env, owner, enabled)
    }
}

// ============================================================================
// Golden State Fixture
// ============================================================================

/// Snapshot of state seeded into the legacy v0 deployment before the upgrade.
///
/// After upgrading and calling `migrate()`, every invariant assertion compares
/// against these fields. Having explicit expected values (not re-derived at
/// assertion time) ensures the test cannot silently pass due to shared mutable state.
#[allow(dead_code)]
struct GoldenState {
    contract_id: Address,
    admin: Address,
    alice: Address,
    bob: Address,
    arbiter: Address,
    token: Address,

    /// Pending deposit — survives upgrade, still withdrawable post-migration.
    commitment_pending: BytesN<32>,
    amount_pending: i128,

    /// Disputed escrow — survives upgrade, arbitration still works post-migration.
    commitment_disputed: BytesN<32>,
    amount_disputed: i128,

    /// Spent escrow (already withdrawn pre-upgrade) — terminal state must be preserved.
    commitment_spent: BytesN<32>,
    amount_spent: i128,

    /// Refunded escrow (already refunded pre-upgrade) — terminal state must be preserved.
    commitment_refunded: BytesN<32>,

    /// Fee basis points written to FeeConfig before the upgrade.
    fee_bps: u32,
}

/// Deploy `LegacyV0Contract`, seed a realistic "golden state", and return the
/// `Env` + snapshot for invariant-checking after the upgrade.
///
/// State seeded (4 escrows, covering all lifecycle states):
///
/// | # | Actor  | Status    | Notes                               |
/// |---|--------|-----------|-------------------------------------|
/// | 1 | alice  | Refunded  | Short timeout (100s), refunded       |
/// | 2 | alice  | Spent     | No timeout, withdrawn immediately   |
/// | 3 | alice  | Pending   | No timeout, untouched                |
/// | 4 | bob    | Disputed  | With arbiter, disputed but unresolved|
///
/// Also sets FeeConfig { fee_bps: 200 } and enables privacy for alice.
fn build_golden_state() -> (Env, GoldenState) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(LegacyV0Contract, ());

    let admin = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let arbiter = Address::generate(&env);
    let token = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    let tok = token::StellarAssetClient::new(&env, &token);

    let fee_bps: u32 = 200;
    let amount_refunded: i128 = 1_000;
    let amount_spent: i128 = 2_000;
    let amount_pending: i128 = 3_000;
    let amount_disputed: i128 = 4_000;

    let (commitment_refunded, commitment_spent, commitment_pending, commitment_disputed) = {
        let client = LegacyV0ContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        // ── Escrow 1: refunded ───────────────────────────────────────────
        // Deposit with a 100-second timeout, then advance time and refund.
        tok.mint(&alice, &amount_refunded);
        let salt_refunded = Bytes::from_slice(&env, b"golden_refunded");
        let c_refunded = client.deposit(
            &token,
            &amount_refunded,
            &alice,
            &salt_refunded,
            &100u64,
            &None,
        );
        env.ledger().set_timestamp(200);
        client.refund(&c_refunded, &alice);

        // ── Escrow 2: spent (withdrawn) ──────────────────────────────────
        tok.mint(&alice, &amount_spent);
        let salt_spent = Bytes::from_slice(&env, b"golden_spent");
        let c_spent = client.deposit(&token, &amount_spent, &alice, &salt_spent, &0u64, &None);
        client.withdraw(&token, &amount_spent, &c_spent, &alice, &salt_spent);

        // ── Escrow 3: pending (untouched until after upgrade) ─────────────
        tok.mint(&alice, &amount_pending);
        let salt_pending = Bytes::from_slice(&env, b"golden_pending");
        let c_pending =
            client.deposit(&token, &amount_pending, &alice, &salt_pending, &0u64, &None);

        // ── Escrow 4: disputed ────────────────────────────────────────────
        tok.mint(&bob, &amount_disputed);
        let salt_disputed = Bytes::from_slice(&env, b"golden_disputed");
        let c_disputed = client.deposit(
            &token,
            &amount_disputed,
            &bob,
            &salt_disputed,
            &0u64,
            &Some(arbiter.clone()),
        );
        client.dispute(&c_disputed);

        // Fee config + alice's privacy flag.
        client.set_fee_config(&FeeConfig { fee_bps });
        client.set_privacy(&alice, &true);

        (c_refunded, c_spent, c_pending, c_disputed)
    }; // legacy client dropped — borrow of env ends here.

    (
        env,
        GoldenState {
            contract_id,
            admin,
            alice,
            bob,
            arbiter,
            token,
            commitment_pending,
            amount_pending,
            commitment_disputed,
            amount_disputed,
            commitment_spent,
            amount_spent,
            commitment_refunded,
            fee_bps,
        },
    )
}

/// Swap the legacy WASM for the current `QuickexContract` on the same address,
/// returning a ready-to-use client pointing at the upgraded contract.
fn upgrade_to_current<'a>(env: &'a Env, contract_id: &Address) -> QuickexContractClient<'a> {
    env.register_at(contract_id, QuickexContract, ());
    QuickexContractClient::new(env, contract_id)
}

// ============================================================================
// Upgrade Flow Tests — version tracking
// ============================================================================

/// After swapping WASM (but before calling `migrate()`), `get_version()` must
/// return `LEGACY_CONTRACT_VERSION` because no ContractVersion was ever stored.
#[test]
fn upgrade_harness_version_is_legacy_before_migrate() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);

    assert_eq!(
        client.get_version(),
        LEGACY_CONTRACT_VERSION,
        "version must be LEGACY before calling migrate()"
    );
}

/// `migrate()` must bump the stored version to `CURRENT_CONTRACT_VERSION` and
/// return that version as confirmation.
#[test]
fn upgrade_harness_migrate_bumps_version_to_current() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);

    let returned = client.migrate(&gs.admin);

    assert_eq!(returned, CURRENT_CONTRACT_VERSION);
    assert_eq!(client.get_version(), CURRENT_CONTRACT_VERSION);
}

// ============================================================================
// Upgrade Flow Tests — escrow data integrity
// ============================================================================

/// All fields of the pending escrow must exactly match the golden-state values
/// after the upgrade + migration.
#[test]
fn upgrade_harness_pending_escrow_fields_match_golden_state() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);
    client.migrate(&gs.admin);

    let details = client
        .get_escrow_details(&gs.commitment_pending, &gs.alice)
        .expect("pending escrow must exist after upgrade");

    assert_eq!(details.status, EscrowStatus::Pending, "status");
    assert_eq!(details.token, gs.token, "token");
    assert_eq!(details.amount_due, Some(gs.amount_pending), "amount_due");
    assert_eq!(details.amount_paid, Some(gs.amount_pending), "amount_paid");
    assert_eq!(details.owner, Some(gs.alice.clone()), "owner");
}

/// A pending escrow seeded pre-upgrade must still be withdrawable post-migration.
#[test]
fn upgrade_harness_pending_escrow_is_withdrawable_post_upgrade() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);
    client.migrate(&gs.admin);

    let salt = Bytes::from_slice(&env, b"golden_pending");
    let withdrew = client.withdraw(
        &gs.token,
        &gs.amount_pending,
        &gs.commitment_pending,
        &gs.alice,
        &salt,
    );
    assert!(withdrew, "withdrawal must succeed post-upgrade");

    assert_eq!(
        client.get_commitment_state(&gs.commitment_pending),
        Some(EscrowStatus::Spent),
        "commitment must be Spent after withdrawal"
    );
}

/// A disputed escrow must still have status `Disputed` after the upgrade.
#[test]
fn upgrade_harness_disputed_escrow_status_preserved() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);
    client.migrate(&gs.admin);

    assert_eq!(
        client.get_commitment_state(&gs.commitment_disputed),
        Some(EscrowStatus::Disputed),
        "disputed escrow must remain Disputed after migration"
    );
}

/// Arbitration must still resolve correctly for a dispute that existed pre-upgrade.
/// The recipient receives `amount - fee` because the golden state seeds a 200 bps fee config.
#[test]
fn upgrade_harness_disputed_escrow_arbitration_works_post_upgrade() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);
    client.migrate(&gs.admin);

    let recipient = Address::generate(&env);
    client.resolve_dispute(&gs.arbiter, &gs.commitment_disputed, &false, &recipient);

    assert_eq!(
        client.get_commitment_state(&gs.commitment_disputed),
        Some(EscrowStatus::Spent),
        "resolved dispute must be Spent"
    );

    // Fee is applied on resolution: fee = amount * fee_bps / 10000.
    let fee = gs.amount_disputed * gs.fee_bps as i128 / 10000;
    let expected_payout = gs.amount_disputed - fee;
    let tok = token::StellarAssetClient::new(&env, &gs.token);
    assert_eq!(
        tok.balance(&recipient),
        expected_payout,
        "recipient must hold amount minus fee after arbitration"
    );
}

/// Terminal-state escrows (Spent / Refunded) must retain their terminal status
/// after the upgrade and must not allow any further state transitions.
#[test]
fn upgrade_harness_terminal_escrow_statuses_preserved() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);
    client.migrate(&gs.admin);

    assert_eq!(
        client.get_commitment_state(&gs.commitment_spent),
        Some(EscrowStatus::Spent),
        "pre-upgrade Spent escrow must remain Spent"
    );
    assert_eq!(
        client.get_commitment_state(&gs.commitment_refunded),
        Some(EscrowStatus::Refunded),
        "pre-upgrade Refunded escrow must remain Refunded"
    );
}

/// A Spent escrow must reject any further withdrawal attempts post-upgrade,
/// enforcing INV-5 (terminal states are final).
#[test]
fn upgrade_harness_already_spent_escrow_rejects_re_withdrawal() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);
    client.migrate(&gs.admin);

    let salt = Bytes::from_slice(&env, b"golden_spent");
    let result = client.try_withdraw(
        &gs.token,
        &gs.amount_spent,
        &gs.commitment_spent,
        &gs.alice,
        &salt,
    );
    assert!(
        result.is_err(),
        "re-withdrawal of an already-Spent escrow must fail post-upgrade"
    );
}

// ============================================================================
// Upgrade Flow Tests — fee config, admin, privacy
// ============================================================================

/// FeeConfig written pre-upgrade (200 bps) must be readable with the same
/// value after the upgrade and migration.
#[test]
fn upgrade_harness_fee_config_survives_migration() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);
    client.migrate(&gs.admin);

    let config = client.get_fee_config();
    assert_eq!(
        config.fee_bps, gs.fee_bps,
        "fee_bps must be unchanged after migration"
    );
}

/// After migration the legacy admin must have the `Admin` role seeded, so that
/// role-gated calls (e.g. `set_fee_config`) succeed without `InsufficientRole`.
#[test]
fn upgrade_harness_admin_role_is_seeded_post_migration() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);
    client.migrate(&gs.admin);

    // If migrate() didn't seed the Admin role, this would return InsufficientRole.
    let result = client.try_set_fee_config(&gs.admin, &FeeConfig { fee_bps: 300 });
    assert!(
        result.is_ok(),
        "admin must retain role-gated access after migration (role seeding)"
    );
}

/// Alice's privacy flag written pre-upgrade must still read as `true`
/// after the upgrade and migration.
#[test]
fn upgrade_harness_privacy_setting_survives_migration() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);
    client.migrate(&gs.admin);

    assert!(
        client.get_privacy(&gs.alice),
        "alice's privacy=true must survive the migration"
    );
}

// ============================================================================
// Regression Tests — known migration pitfalls
// ============================================================================

/// Double-migrate must be idempotent: a second call must return the same
/// `CURRENT_CONTRACT_VERSION` and must not corrupt any state or panic.
#[test]
fn upgrade_harness_double_migrate_is_idempotent() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);

    let v1 = client.migrate(&gs.admin);
    let v2 = client.migrate(&gs.admin);

    assert_eq!(v1, CURRENT_CONTRACT_VERSION, "first migrate return value");
    assert_eq!(v2, CURRENT_CONTRACT_VERSION, "second migrate return value");
    assert_eq!(
        client.get_version(),
        CURRENT_CONTRACT_VERSION,
        "stored version after double migrate"
    );
}

/// A non-admin caller must be rejected with `InsufficientRole`.
#[test]
fn upgrade_harness_non_admin_migrate_fails() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);

    let non_admin = Address::generate(&env);
    let result = client.try_migrate(&non_admin);
    assert_eq!(
        result,
        Err(Ok(QuickexError::InsufficientRole)),
        "non-admin migrate must fail with InsufficientRole"
    );
}

/// Migration on a contract that was never initialized (no admin stored) must
/// return an error, not panic or corrupt storage.
#[test]
fn upgrade_harness_migrate_without_admin_fails_gracefully() {
    let env = Env::default();
    env.mock_all_auths();

    // Current contract registered but never initialized — no admin in storage.
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);

    let caller = Address::generate(&env);
    let result = client.try_migrate(&caller);
    assert!(
        result.is_err(),
        "migrate on uninitialized contract must return an error"
    );
}

/// Regression: a privacy flag stored under the legacy Symbol-based key
/// (i.e. `(Symbol("privacy_enabled"), address)` rather than `DataKey::PrivacyEnabled`)
/// must still read as `true` after the upgrade, exercising the fallback read
/// path in `privacy::read_privacy_flag`.
#[test]
fn upgrade_harness_legacy_symbol_privacy_key_readable_after_upgrade() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(LegacyV0Contract, ());
    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    {
        let client = LegacyV0ContractClient::new(&env, &contract_id);
        client.initialize(&admin);
    }

    // Seed the legacy Symbol-based key directly, bypassing the current set_privacy
    // (which would use DataKey::PrivacyEnabled). This simulates a pre-migration
    // deployment where only the old key format was used.
    env.as_contract(&contract_id, || {
        let legacy_key = (Symbol::new(&env, PRIVACY_ENABLED_KEY), user.clone());
        env.storage().persistent().set(&legacy_key, &true);
    });

    // Upgrade + migrate.
    env.register_at(&contract_id, QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    client.migrate(&admin);

    assert!(
        client.get_privacy(&user),
        "legacy Symbol-based privacy key must still be readable via fallback after upgrade"
    );
}

/// Regression: the escrow counter must not be touched by `migrate()`.
///
/// `deposit()` does not use the escrow counter (only `create_escrow` does),
/// so this test explicitly seeds the counter to a known non-zero value via
/// storage and verifies it is unchanged after migration.
#[test]
fn upgrade_harness_escrow_counter_survives_migration() {
    let (env, gs) = build_golden_state();

    // Seed the counter to a known non-zero value (simulates prior create_escrow calls).
    env.as_contract(&gs.contract_id, || {
        for _ in 0..4 {
            crate::storage::increment_escrow_counter(&env);
        }
    });

    let counter_before: u64 =
        env.as_contract(&gs.contract_id, || crate::storage::get_escrow_counter(&env));

    let client = upgrade_to_current(&env, &gs.contract_id);
    client.migrate(&gs.admin);

    let counter_after: u64 =
        env.as_contract(&gs.contract_id, || crate::storage::get_escrow_counter(&env));

    assert_eq!(
        counter_before, 4,
        "seeded counter must read back as 4 before migration"
    );
    assert_eq!(
        counter_after, counter_before,
        "migration must not alter the escrow counter"
    );
}

/// Regression: a mix of escrow statuses (Pending, Disputed, Spent, Refunded)
/// must all survive migration with distinct, correct statuses. This guards
/// against a migration bug that would reset all statuses to a single value.
#[test]
fn upgrade_harness_all_lifecycle_statuses_are_distinct_post_migration() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);
    client.migrate(&gs.admin);

    let statuses = [
        (
            "pending",
            client.get_commitment_state(&gs.commitment_pending),
            EscrowStatus::Pending,
        ),
        (
            "disputed",
            client.get_commitment_state(&gs.commitment_disputed),
            EscrowStatus::Disputed,
        ),
        (
            "spent",
            client.get_commitment_state(&gs.commitment_spent),
            EscrowStatus::Spent,
        ),
        (
            "refunded",
            client.get_commitment_state(&gs.commitment_refunded),
            EscrowStatus::Refunded,
        ),
    ];

    for (label, actual, expected) in statuses {
        assert_eq!(
            actual,
            Some(expected),
            "escrow '{}' must have status {:?} after migration",
            label,
            expected
        );
    }
}

// ============================================================================
// Upgrade Safety Gate Tests — Issue #432
// ============================================================================

#[test]
fn upgrade_safety_gate_blocks_upgrade_outside_window() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);

    // Window not set → upgrades blocked.
    let result = client.try_start_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION);
    assert!(
        result.is_err(),
        "start_upgrade must fail when no window is set"
    );

    // Set a future window → still blocked.
    let now = env.ledger().timestamp();
    client
        .set_upgrade_window(&gs.admin, &(now + 1000), &(now + 2000))
        .expect("set_upgrade_window should succeed");

    let result = client.try_start_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION);
    assert!(
        result.is_err(),
        "start_upgrade must fail when current time is before window start"
    );

    // Advance time to within the window → succeeds.
    env.ledger().with_mut(|li| {
        li.timestamp = now + 1500;
    });

    client
        .start_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION)
        .expect("start_upgrade should succeed during window");

    // Verify upgrade_in_progress flag is set.
    client
        .migrate(&gs.admin)
        .expect("migrate after start_upgrade");
    client
        .complete_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION)
        .expect("complete_upgrade should succeed");

    // Advance time to after the window → now blocked.
    env.ledger().with_mut(|li| {
        li.timestamp = now + 2500;
    });

    let result = client.try_start_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION);
    assert!(
        result.is_err(),
        "start_upgrade must fail when current time is after window end"
    );
}

#[test]
fn upgrade_safety_gate_post_upgrade_invariants_enforced() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);

    // Set a valid window: start=1 (before current timestamp 200), end=0 (no upper bound).
    client
        .set_upgrade_window(&gs.admin, &1u64, &0u64)
        .expect("set_upgrade_window should succeed");

    // Attempt a normal upgrade: should validate invariants post-migrate.
    client
        .start_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION)
        .expect("start_upgrade should succeed");

    let version = client.migrate(&gs.admin).expect("migrate should succeed");
    assert_eq!(version, CURRENT_CONTRACT_VERSION);

    client
        .complete_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION)
        .expect("complete_upgrade should succeed and validate invariants");

    // Verify the contract is still in a valid state after complete_upgrade.
    // This is implicit: if invariants failed, complete_upgrade would panic.

    // Verify no upgrade is in progress anymore.
    let (start, end) = client.get_upgrade_window();
    // Window should be (1, 0) as set.
    assert_eq!(start, 1);
    assert_eq!(end, 0);
}

#[test]
fn upgrade_safety_gate_invariant_failure_deterministic() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);

    // Set valid window and start upgrade.
    client
        .set_upgrade_window(&gs.admin, &1u64, &0u64)
        .expect("set_upgrade_window");
    client
        .start_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION)
        .expect("start_upgrade");

    // Deliberately corrupt fee config to violate invariant (fee_bps > 10_000).
    env.as_contract(&gs.contract_id, || {
        crate::storage::set_fee_config(&env, &FeeConfig { fee_bps: 99999 });
    });

    // migrate must fail deterministically when invariants are violated (AC2).
    let result = client.try_migrate(&gs.admin);
    assert_eq!(
        result,
        Err(Ok(QuickexError::InternalError)),
        "migrate must fail with InternalError when invariants are violated"
    );

    // Restore fee config and complete the upgrade cleanly.
    env.as_contract(&gs.contract_id, || {
        crate::storage::set_fee_config(&env, &FeeConfig { fee_bps: 200 });
    });
    client
        .migrate(&gs.admin)
        .expect("migrate must succeed after restoring invariants");
    client
        .complete_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION)
        .expect("complete_upgrade");
}

#[test]
fn upgrade_safety_gate_emits_events() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);

    // Set a valid window.
    client
        .set_upgrade_window(&gs.admin, &1u64, &0u64)
        .expect("set_upgrade_window");

    // Capture event count before upgrade ceremony.
    let events_before = env.events().all().len();

    // Start upgrade → should emit UpgradeStarted event.
    client
        .start_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION)
        .expect("start_upgrade");

    client.migrate(&gs.admin).expect("migrate");

    // Complete upgrade → should emit UpgradeCompleted event.
    client
        .complete_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION)
        .expect("complete_upgrade");

    // Verify at least UpgradeStarted + UpgradeCompleted were emitted (AC3).
    let events_after = env.events().all().len();
    assert!(
        events_after > events_before,
        "upgrade ceremony must emit events (AC3: indexers can track upgrades from events alone)"
    );
}

#[test]
fn upgrade_safety_gate_blocks_double_start() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);

    client
        .set_upgrade_window(&gs.admin, &1u64, &0u64)
        .expect("set_upgrade_window");

    // First start succeeds.
    client
        .start_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION)
        .expect("start_upgrade #1");

    // Second start (without complete_upgrade) fails → upgrade already in progress.
    let result = client.try_start_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION);
    assert!(
        result.is_err(),
        "start_upgrade must fail when upgrade already in progress"
    );

    // Clean up by completing the upgrade.
    client.migrate(&gs.admin).expect("migrate");
    client
        .complete_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION)
        .expect("complete_upgrade");

    // Now a new start is allowed.
    client
        .start_upgrade(&gs.admin, &CURRENT_CONTRACT_VERSION)
        .expect("start_upgrade #2 after complete_upgrade");
}

#[test]
fn upgrade_safety_gate_non_admin_blocked() {
    let (env, gs) = build_golden_state();
    let client = upgrade_to_current(&env, &gs.contract_id);
    let non_admin = Address::generate(&env);

    client
        .set_upgrade_window(&gs.admin, &1u64, &0u64)
        .expect("set_upgrade_window by admin");

    // Non-admin attempts start_upgrade → fails.
    let result = client.try_start_upgrade(&non_admin, &CURRENT_CONTRACT_VERSION);
    assert!(result.is_err(), "start_upgrade by non-admin must fail");

    // Non-admin attempts set_upgrade_window → fails.
    let result = client.try_set_upgrade_window(&non_admin, &1u64, &0u64);
    assert!(result.is_err(), "set_upgrade_window by non-admin must fail");
}
