//! Tests for Issue #866 (SC-W8-05): fee treasury withdrawal entrypoint.
//!
//! `TestContext::with_fees` always configures a platform wallet, which makes
//! `fee_router` push the platform-fee portion out immediately — no treasury
//! ever accrues. These tests instead configure only `fee_bps` (no platform
//! wallet, no rotated collector), so `fee_router::active_collector` returns
//! `None` and the platform-fee portion is credited to the accrued-fee ledger
//! instead, exercising the actual code path this ticket adds.

use soroban_sdk::{testutils::Address as _, Address};

use crate::{
    assert_helpers::assert_qx_err, errors::QuickexError, test_context::TestContext,
    types::FeeConfig,
};

const FEE_BPS: u32 = 250; // 2.5%

/// `with_admin()` + fee_bps set, but deliberately *no* platform wallet /
/// collector, so settled fees accrue in the contract instead of being pushed out.
fn ctx_with_accruing_fees() -> TestContext<'static> {
    let ctx = TestContext::with_admin();
    ctx.client
        .set_fee_config(&ctx.admin, &FeeConfig { fee_bps: FEE_BPS });
    ctx
}

/// Deposit `amount` from `owner` and immediately withdraw it in full,
/// returning the fee that was accrued as a result.
fn settle(ctx: &TestContext, owner: &Address, amount: i128, salt: &[u8]) {
    let commitment = ctx.simple_deposit(owner, amount, salt);
    ctx.client.withdraw(
        &ctx.token,
        &amount,
        &commitment,
        owner,
        &ctx.salt(salt),
        &0u64,
        &u64::MAX,
    );
}

fn expected_fee(amount: i128) -> i128 {
    amount * FEE_BPS as i128 / 10_000
}

// ============================================================================
// AC3: accrued balance is queryable per asset; fees actually accrue
// ============================================================================

#[test]
fn test_fee_accrues_when_no_collector_configured() {
    let ctx = ctx_with_accruing_fees();
    let owner = ctx.alice.clone();
    let amount = 10_000;

    assert_eq!(ctx.client.get_accrued_fee_balance(&ctx.token), 0);

    settle(&ctx, &owner, amount, b"accrue");

    let fee = expected_fee(amount);
    assert_eq!(ctx.client.get_accrued_fee_balance(&ctx.token), fee);
    assert_eq!(ctx.balance(&owner), amount - fee);
}

// ============================================================================
// AC1 + AC6: full withdrawal, partial withdrawal
// ============================================================================

#[test]
fn test_withdraw_fees_full_withdrawal_succeeds() {
    let ctx = ctx_with_accruing_fees();
    settle(&ctx, &ctx.alice.clone(), 10_000, b"full");
    let accrued = ctx.client.get_accrued_fee_balance(&ctx.token);
    assert!(accrued > 0);

    let recipient = Address::generate(&ctx.env);
    ctx.client
        .withdraw_fees(&ctx.admin, &ctx.token, &accrued, &recipient);

    assert_eq!(ctx.balance(&recipient), accrued);
    assert_eq!(ctx.client.get_accrued_fee_balance(&ctx.token), 0);
}

#[test]
fn test_withdraw_fees_partial_withdrawal_succeeds() {
    let ctx = ctx_with_accruing_fees();
    settle(&ctx, &ctx.alice.clone(), 10_000, b"partial");
    let accrued = ctx.client.get_accrued_fee_balance(&ctx.token);
    assert!(accrued >= 2);

    let recipient = Address::generate(&ctx.env);
    let half = accrued / 2;
    ctx.client
        .withdraw_fees(&ctx.admin, &ctx.token, &half, &recipient);

    assert_eq!(ctx.balance(&recipient), half);
    assert_eq!(
        ctx.client.get_accrued_fee_balance(&ctx.token),
        accrued - half
    );

    // The remainder can still be withdrawn afterward.
    let remaining = ctx.client.get_accrued_fee_balance(&ctx.token);
    ctx.client
        .withdraw_fees(&ctx.admin, &ctx.token, &remaining, &recipient);
    assert_eq!(ctx.balance(&recipient), accrued);
    assert_eq!(ctx.client.get_accrued_fee_balance(&ctx.token), 0);
}

// ============================================================================
// AC6: over-withdrawal rejection, unauthorized caller
// ============================================================================

#[test]
fn test_withdraw_fees_over_withdrawal_rejected() {
    let ctx = ctx_with_accruing_fees();
    settle(&ctx, &ctx.alice.clone(), 10_000, b"over");
    let accrued = ctx.client.get_accrued_fee_balance(&ctx.token);

    let recipient = Address::generate(&ctx.env);
    let result = ctx
        .client
        .try_withdraw_fees(&ctx.admin, &ctx.token, &(accrued + 1), &recipient);
    assert_qx_err(result, QuickexError::Overpayment);

    // Balance is untouched by the rejected attempt.
    assert_eq!(ctx.client.get_accrued_fee_balance(&ctx.token), accrued);
    assert_eq!(ctx.balance(&recipient), 0);
}

#[test]
fn test_withdraw_fees_rejects_zero_accrued_balance() {
    let ctx = TestContext::with_admin();
    let recipient = Address::generate(&ctx.env);
    let result = ctx
        .client
        .try_withdraw_fees(&ctx.admin, &ctx.token, &1, &recipient);
    assert_qx_err(result, QuickexError::Overpayment);
}

#[test]
fn test_withdraw_fees_rejects_zero_or_negative_amount() {
    let ctx = ctx_with_accruing_fees();
    settle(&ctx, &ctx.alice.clone(), 10_000, b"zero_amt");
    let recipient = Address::generate(&ctx.env);

    let zero = ctx
        .client
        .try_withdraw_fees(&ctx.admin, &ctx.token, &0, &recipient);
    assert_qx_err(zero, QuickexError::InvalidAmount);

    let negative = ctx
        .client
        .try_withdraw_fees(&ctx.admin, &ctx.token, &-1, &recipient);
    assert_qx_err(negative, QuickexError::InvalidAmount);
}

#[test]
fn test_withdraw_fees_unauthorized_caller_rejected() {
    let ctx = ctx_with_accruing_fees();
    settle(&ctx, &ctx.alice.clone(), 10_000, b"unauth");
    let accrued = ctx.client.get_accrued_fee_balance(&ctx.token);

    let not_admin = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);
    let result = ctx
        .client
        .try_withdraw_fees(&not_admin, &ctx.token, &accrued, &recipient);
    assert_qx_err(result, QuickexError::InsufficientRole);

    // Balance is untouched by the rejected attempt.
    assert_eq!(ctx.client.get_accrued_fee_balance(&ctx.token), accrued);
}

// ============================================================================
// AC5: pause and emergency mode policy
// ============================================================================

#[test]
fn test_withdraw_fees_blocked_while_globally_paused() {
    let ctx = ctx_with_accruing_fees();
    settle(&ctx, &ctx.alice.clone(), 10_000, b"paused");
    let accrued = ctx.client.get_accrued_fee_balance(&ctx.token);
    let recipient = Address::generate(&ctx.env);

    ctx.client.set_paused(&ctx.admin, &true, &0u32);

    let result = ctx
        .client
        .try_withdraw_fees(&ctx.admin, &ctx.token, &accrued, &recipient);
    assert_qx_err(result, QuickexError::ContractPaused);
}

#[test]
fn test_withdraw_fees_blocked_during_emergency_mode() {
    let ctx = ctx_with_accruing_fees();
    settle(&ctx, &ctx.alice.clone(), 10_000, b"emergency");
    let accrued = ctx.client.get_accrued_fee_balance(&ctx.token);
    let recipient = Address::generate(&ctx.env);

    ctx.client.activate_emergency_mode(&ctx.admin);

    let result = ctx
        .client
        .try_withdraw_fees(&ctx.admin, &ctx.token, &accrued, &recipient);
    assert_qx_err(result, QuickexError::ContractPaused);
}

// ============================================================================
// AC2: withdrawal cannot touch escrowed principal (accounting invariant)
// ============================================================================

#[test]
fn test_withdrawal_cannot_touch_escrowed_principal() {
    let ctx = ctx_with_accruing_fees();

    // Escrow A: will be settled, generating an accrued fee.
    let alice = ctx.alice.clone();
    let a_amount = 10_000;
    settle(&ctx, &alice, a_amount, b"invariant_a");
    let accrued_fee = ctx.client.get_accrued_fee_balance(&ctx.token);
    assert!(accrued_fee > 0);

    // Escrow B: stays Pending — its principal must remain untouchable.
    let bob = ctx.bob.clone();
    let b_amount = 5_000;
    let b_salt = b"invariant_b";
    let b_commitment = ctx.simple_deposit(&bob, b_amount, b_salt);

    let contract_address = ctx.client.address.clone();
    // The contract's own balance must now exactly cover B's principal plus
    // the accrued fee — nothing more, nothing less.
    assert_eq!(
        ctx.balance(&contract_address),
        b_amount + accrued_fee,
        "contract balance must equal escrowed principal plus accrued fees"
    );

    // Withdraw the *entire* accrued fee balance.
    let recipient = Address::generate(&ctx.env);
    ctx.client
        .withdraw_fees(&ctx.admin, &ctx.token, &accrued_fee, &recipient);

    // B's principal must be fully intact — the contract balance now equals
    // exactly B's principal, not a cent less.
    assert_eq!(
        ctx.balance(&contract_address),
        b_amount,
        "fee withdrawal must not have touched escrow B's principal"
    );
    assert_eq!(ctx.client.get_accrued_fee_balance(&ctx.token), 0);

    // Prove it isn't just bookkeeping: B can still be withdrawn in full.
    ctx.client.withdraw(
        &ctx.token,
        &b_amount,
        &b_commitment,
        &bob,
        &ctx.salt(b_salt),
        &0u64,
        &u64::MAX,
    );
    let b_fee = expected_fee(b_amount);
    assert_eq!(ctx.balance(&bob), b_amount - b_fee);
}
