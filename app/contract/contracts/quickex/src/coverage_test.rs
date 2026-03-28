//! Coverage-completion tests for QuickEx contract modules.
//!
//! This module uses [`TestContext`] and [`assert_helpers`] to cover code paths
//! not reached by the existing integration tests in `test.rs`.
//!
//! Every test below demonstrates the **< 10 lines of setup** acceptance criterion.
//! One call to `TestContext::new()`, `TestContext::with_admin()`, or
//! `TestContext::with_fees()` is all that is needed before writing test logic.
//!
//! ## Coverage areas
//!
//! | Section                          | Paths covered                                  |
//! |----------------------------------|------------------------------------------------|
//! | Level-based privacy API          | `enable_privacy`, `privacy_status`,            |
//! |                                  | `privacy_history` (level ordering, edge cases) |
//! | `deposit_with_commitment` errors | `CommitmentAlreadyExists`, arbiter storage     |
//! | Refund edge cases                | `EscrowNotExpired` (no-expiry + before-expiry) |
//! | `verify_proof_view` expiry       | Returns `false` for expired, pending escrow    |
//! | Assertion helpers smoke tests    | Each helper exercised end-to-end               |
//! | TestContext demos                | Full lifecycle, admin, fees, dispute           |
//!   (<= 10 lines apiece)            |                                                |

use crate::{
    assert_helpers::{
        assert_commitment_invalid, assert_commitment_valid, assert_escrow_disputed,
        assert_escrow_pending, assert_escrow_refunded, assert_escrow_spent, assert_qx_err,
    },
    errors::QuickexError,
    test_context::TestContext,
};
use soroban_sdk::BytesN;

// ============================================================================
// Level-based privacy API (enable_privacy / privacy_status / privacy_history)
// ============================================================================

/// `enable_privacy` sets the numeric level and records an entry in history.
#[test]
fn test_enable_privacy_sets_level_and_records_history() {
    let ctx = TestContext::new();
    let account = ctx.alice.clone();

    // Default: no level set, empty history
    assert_eq!(ctx.client.privacy_status(&account), None);
    assert_eq!(ctx.client.privacy_history(&account).len(), 0);

    // Enable privacy at level 1
    let ok = ctx.client.enable_privacy(&account, &1);
    assert!(ok);
    assert_eq!(ctx.client.privacy_status(&account), Some(1));
    assert_eq!(ctx.client.privacy_history(&account).len(), 1);
}

/// Multiple `enable_privacy` calls each append to history (newest first).
#[test]
fn test_enable_privacy_history_appends_newest_first() {
    let ctx = TestContext::new();
    let account = ctx.alice.clone();

    ctx.client.enable_privacy(&account, &0);
    ctx.client.enable_privacy(&account, &1);
    ctx.client.enable_privacy(&account, &2);

    let history = ctx.client.privacy_history(&account);
    // `add_privacy_history` uses `push_front` → newest value at index 0
    assert_eq!(history.get(0), Some(2u32));
    assert_eq!(history.get(1), Some(1u32));
    assert_eq!(history.get(2), Some(0u32));

    // privacy_status reflects the most-recently-set level
    assert_eq!(ctx.client.privacy_status(&account), Some(2));
}

/// Level 0 is a valid privacy level (represents "off" for the numeric API).
#[test]
fn test_enable_privacy_level_zero_is_valid() {
    let ctx = TestContext::new();
    ctx.client.enable_privacy(&ctx.bob.clone(), &0);
    assert_eq!(ctx.client.privacy_status(&ctx.bob), Some(0));
    assert_eq!(ctx.client.privacy_history(&ctx.bob).len(), 1);
}

/// `enable_privacy` for a different account does not affect another account.
#[test]
fn test_enable_privacy_is_per_account() {
    let ctx = TestContext::new();
    ctx.client.enable_privacy(&ctx.alice.clone(), &5);
    assert_eq!(ctx.client.privacy_status(&ctx.alice), Some(5));
    // Bob's level is unaffected
    assert_eq!(ctx.client.privacy_status(&ctx.bob), None);
}

// ============================================================================
// deposit_with_commitment — error paths
// ============================================================================

/// Depositing twice with the same raw commitment must fail with CommitmentAlreadyExists.
#[test]
fn test_deposit_with_commitment_duplicate_fails() {
    let ctx = TestContext::new();
    ctx.mint(&ctx.alice.clone(), 1000);
    let commitment = BytesN::from_array(&ctx.env, &[0x42u8; 32]);

    // First deposit succeeds
    ctx.client
        .deposit_with_commitment(&ctx.alice, &ctx.token, &500, &commitment, &0, &None);

    // Second deposit with the same commitment must fail
    ctx.mint(&ctx.alice.clone(), 500);
    assert_qx_err(
        ctx.client.try_deposit_with_commitment(
            &ctx.alice,
            &ctx.token,
            &500,
            &commitment,
            &0,
            &None,
        ),
        QuickexError::CommitmentAlreadyExists,
    );
}

/// `deposit_with_commitment` with an arbiter stores the arbiter, visible via details.
#[test]
fn test_deposit_with_commitment_with_arbiter_stores_arbiter() {
    let ctx = TestContext::new();
    ctx.mint(&ctx.alice.clone(), 1000);
    let commitment = BytesN::from_array(&ctx.env, &[0xABu8; 32]);

    ctx.client.deposit_with_commitment(
        &ctx.alice,
        &ctx.token,
        &1000,
        &commitment,
        &0,
        &Some(ctx.arbiter.clone()),
    );

    assert_escrow_pending(&ctx.client, &commitment);

    // Arbiter must be visible in the escrow details when queried as arbiter
    let view = ctx
        .client
        .get_escrow_details(&commitment, &ctx.arbiter)
        .unwrap();
    assert_eq!(view.arbiter, Some(ctx.arbiter.clone()));
}

/// `deposit_with_commitment` with a zero amount must fail.
#[test]
fn test_deposit_with_commitment_zero_amount_fails() {
    let ctx = TestContext::new();
    let commitment = BytesN::from_array(&ctx.env, &[0x01u8; 32]);
    assert_qx_err(
        ctx.client
            .try_deposit_with_commitment(&ctx.alice, &ctx.token, &0, &commitment, &0, &None),
        QuickexError::InvalidAmount,
    );
}

/// `deposit_with_commitment` blocks when DepositWithCommitment feature is paused.
#[test]
fn test_deposit_with_commitment_paused_feature_fails() {
    use crate::storage::PauseFlag;
    let ctx = TestContext::with_admin();
    ctx.mint(&ctx.alice.clone(), 1000);

    ctx.client
        .pause_features(&ctx.admin, &(PauseFlag::DepositWithCommitment as u64));

    let commitment = BytesN::from_array(&ctx.env, &[0xCDu8; 32]);
    assert_qx_err(
        ctx.client.try_deposit_with_commitment(
            &ctx.alice,
            &ctx.token,
            &500,
            &commitment,
            &0,
            &None,
        ),
        QuickexError::OperationPaused,
    );
}

// ============================================================================
// refund — EscrowNotExpired edge cases
// ============================================================================

/// Refund on a never-expiring escrow (`expires_at == 0`) must fail.
#[test]
fn test_refund_never_expiring_escrow_fails() {
    let ctx = TestContext::new();
    let commitment = ctx.simple_deposit(&ctx.alice.clone(), 500, b"no_expiry_refund");

    // expires_at == 0 means the escrow never expires → refund must be rejected
    assert_qx_err(
        ctx.client.try_refund(&commitment, &ctx.alice),
        QuickexError::EscrowNotExpired,
    );
}

/// Refund before the timeout window must fail even for a timed escrow.
#[test]
fn test_refund_before_timeout_window_fails() {
    let ctx = TestContext::new();
    ctx.mint(&ctx.alice.clone(), 1000);
    let commitment = ctx.client.deposit(
        &ctx.token,
        &1000,
        &ctx.alice,
        &ctx.salt(b"timed_refund"),
        &3600,
        &None,
    );

    // Time has not advanced — refund is not yet available
    assert_qx_err(
        ctx.client.try_refund(&commitment, &ctx.alice),
        QuickexError::EscrowNotExpired,
    );
}

// ============================================================================
// verify_proof_view — expired escrow path
// ============================================================================

/// `verify_proof_view` must return `false` for an expired (still-Pending) escrow.
#[test]
fn test_verify_proof_view_expired_returns_false() {
    let ctx = TestContext::new();
    ctx.mint(&ctx.alice.clone(), 1000);
    let timeout = 100u64;
    ctx.client.deposit(
        &ctx.token,
        &1000,
        &ctx.alice,
        &ctx.salt(b"proof_exp"),
        &timeout,
        &None,
    );

    // Advance past expiry
    ctx.advance_time(timeout + 1);

    // verify_proof_view must return false for an expired escrow
    let ok = ctx
        .client
        .verify_proof_view(&1000, &ctx.salt(b"proof_exp"), &ctx.alice);
    assert!(!ok, "verify_proof_view should be false for expired escrow");
}

// ============================================================================
// Assertion helpers — smoke-test each public function end-to-end
// ============================================================================

/// `assert_escrow_pending` and `assert_escrow_spent` fire correctly.
#[test]
fn test_assert_helpers_pending_and_spent() {
    let ctx = TestContext::new();
    let commitment = ctx.simple_deposit(&ctx.alice.clone(), 500, b"h_pending");

    assert_escrow_pending(&ctx.client, &commitment);

    ctx.client.withdraw(
        &ctx.token,
        &500,
        &commitment,
        &ctx.alice,
        &ctx.salt(b"h_pending"),
    );
    assert_escrow_spent(&ctx.client, &commitment);
}

/// `assert_escrow_disputed` and `assert_escrow_refunded` fire correctly.
#[test]
fn test_assert_helpers_disputed_and_refunded() {
    let ctx = TestContext::new();
    let commitment = ctx.deposit_with_arbiter(&ctx.alice.clone(), 500, b"h_dispute", 3600);

    ctx.client.dispute(&commitment);
    assert_escrow_disputed(&ctx.client, &commitment);

    // Resolve for owner → Refunded
    ctx.client.resolve_dispute(&commitment, &true, &ctx.bob);
    assert_escrow_refunded(&ctx.client, &commitment);
}

/// `assert_commitment_valid` and `assert_commitment_invalid` fire correctly.
#[test]
fn test_assert_helpers_commitment_valid_and_invalid() {
    let ctx = TestContext::new();
    let salt = ctx.salt(b"helper_salt");
    let commitment = ctx
        .client
        .create_amount_commitment(&ctx.alice, &1000, &salt);

    assert_commitment_valid(&ctx.client, &commitment, &ctx.alice, 1000, &salt);

    let wrong_salt = ctx.salt(b"wrong_salt");
    assert_commitment_invalid(&ctx.client, &commitment, &ctx.alice, 1000, &wrong_salt);
    assert_commitment_invalid(&ctx.client, &commitment, &ctx.alice, 9_999, &salt);
}

// ============================================================================
// TestContext integration demos — each ≤ 10 lines of setup + assertion
// ============================================================================

/// Full escrow lifecycle (deposit → withdraw → verify balance) in ≤ 10 lines.
#[test]
fn test_demo_full_lifecycle_under_10_lines() {
    let ctx = TestContext::new(); // 1
    let c = ctx.simple_deposit(&ctx.alice.clone(), 1_000, b"ten"); // 2
    assert_escrow_pending(&ctx.client, &c); // 3
    ctx.client
        .withdraw(&ctx.token, &1_000, &c, &ctx.alice, &ctx.salt(b"ten")); // 4
    assert_escrow_spent(&ctx.client, &c); // 5
    assert_eq!(ctx.balance(&ctx.alice), 1_000); // 6
}

/// Admin initialization, pause, and unpause in ≤ 10 lines.
#[test]
fn test_demo_admin_lifecycle_under_10_lines() {
    let ctx = TestContext::with_admin(); // 1
    assert_eq!(ctx.client.get_admin(), Some(ctx.admin.clone())); // 2
    ctx.client.set_paused(&ctx.admin, &true); // 3
    assert!(ctx.client.is_paused()); // 4
    ctx.client.set_paused(&ctx.admin, &false); // 5
    assert!(!ctx.client.is_paused()); // 6
}

/// Fee-configured withdrawal splits funds correctly in ≤ 10 lines.
#[test]
fn test_demo_fee_withdrawal_under_10_lines() {
    let ctx = TestContext::with_fees(1000); // 1 (10%)
    let c = ctx.simple_deposit(&ctx.alice.clone(), 1_000, b"fee_10"); // 2
    ctx.client
        .withdraw(&ctx.token, &1_000, &c, &ctx.alice, &ctx.salt(b"fee_10")); // 3
    assert_eq!(ctx.balance(&ctx.alice), 900); // 4
    assert_eq!(ctx.balance(&ctx.platform_wallet), 100); // 5
}

/// Dispute flow from open to resolution in ≤ 10 lines.
#[test]
fn test_demo_dispute_flow_under_10_lines() {
    let ctx = TestContext::new(); // 1
    let c = ctx.deposit_with_arbiter(&ctx.alice.clone(), 2_000, b"dp10", 3600); // 2
    ctx.client.dispute(&c); // 3
    assert_escrow_disputed(&ctx.client, &c); // 4
    ctx.client.resolve_dispute(&c, &false, &ctx.bob); // 5  (pay bob)
    assert_escrow_spent(&ctx.client, &c); // 6
    assert_eq!(ctx.balance(&ctx.bob), 2_000); // 7
}

/// Expiry and refund in ≤ 10 lines.
#[test]
fn test_demo_expiry_and_refund_under_10_lines() {
    let ctx = TestContext::new(); // 1
    ctx.mint(&ctx.alice.clone(), 500); // 2
    let c = ctx
        .client
        .deposit(&ctx.token, &500, &ctx.alice, &ctx.salt(b"exp"), &100, &None); // 3
    ctx.advance_time(101); // 4
    ctx.client.refund(&c, &ctx.alice); // 5
    assert_escrow_refunded(&ctx.client, &c); // 6
    assert_eq!(ctx.balance(&ctx.alice), 500); // 7
}

/// Privacy toggle and balance privacy using TestContext in ≤ 10 lines.
#[test]
fn test_demo_privacy_toggle_under_10_lines() {
    let ctx = TestContext::new(); // 1
    assert!(!ctx.client.get_privacy(&ctx.alice)); // 2
    ctx.client.set_privacy(&ctx.alice, &true); // 3
    assert!(ctx.client.get_privacy(&ctx.alice)); // 4
    ctx.client.set_privacy(&ctx.alice, &false); // 5
    assert!(!ctx.client.get_privacy(&ctx.alice)); // 6
}
