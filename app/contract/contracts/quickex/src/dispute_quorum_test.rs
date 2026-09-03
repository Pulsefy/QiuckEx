//! Tests for Issue #865 (SC-W8-04): dispute quorum configuration and vote expiry.
//!
//! There is no production entrypoint that assigns multiple arbiters to an
//! escrow yet (multi-sig assignment is out of scope for this ticket — see
//! `entry.arbiters` / `entry.arbiter_threshold` docs), so these tests build a
//! multi-sig `Disputed` escrow the same way the rest of the test suite
//! constructs raw fixtures: deposit with the legacy single-arbiter path, then
//! directly write the extended arbiter fields via `storage::put_escrow`
//! before opening the dispute through the real `dispute()` entrypoint.

use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Vec};

use crate::{
    assert_helpers::assert_qx_err,
    dispute_quorum::{DisputeQuorumConfig, MAX_QUORUM, MAX_VOTE_TTL_SECS, MIN_VOTE_TTL_SECS},
    errors::QuickexError,
    storage::{get_escrow, put_escrow},
    test_context::TestContext,
    types::EscrowStatus,
};

const VOTE_TTL: u64 = MIN_VOTE_TTL_SECS; // 3600s; smallest legal window, easiest to reason about

/// Deposit, then rewrite the stored entry with `arbiters`/`arbiter_threshold`,
/// then open the dispute through the real `dispute()` entrypoint.
fn open_multi_sig_dispute(
    ctx: &TestContext,
    owner: &Address,
    arbiters: &[Address],
    threshold: u32,
    amount: i128,
    salt: &[u8],
) -> BytesN<32> {
    let commitment = ctx.deposit_with_arbiter(owner, amount, salt, 0);
    let commitment_bytes: Bytes = commitment.clone().into();

    ctx.env.as_contract(&ctx.client.address, || {
        let mut entry = get_escrow(&ctx.env, &commitment_bytes).unwrap();
        let mut arbiters_vec = Vec::new(&ctx.env);
        for a in arbiters {
            arbiters_vec.push_back(a.clone());
        }
        entry.arbiters = arbiters_vec;
        entry.arbiter_threshold = threshold;
        put_escrow(&ctx.env, &commitment_bytes, &entry);
    });

    ctx.client.dispute(&commitment);
    commitment
}

fn three_arbiters(ctx: &TestContext) -> (Address, Address, Address) {
    (
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
    )
}

// ============================================================================
// AC1: quorum configurable by admin within hard bounds
// ============================================================================

#[test]
fn test_set_dispute_quorum_config_within_bounds_succeeds() {
    let ctx = TestContext::with_admin();
    let config = DisputeQuorumConfig {
        quorum: 3,
        vote_ttl_secs: VOTE_TTL,
    };
    ctx.client.set_dispute_quorum_config(&ctx.admin, &config);
    assert_eq!(ctx.client.get_dispute_quorum_config(), config);
}

#[test]
fn test_set_dispute_quorum_config_rejects_quorum_below_min() {
    let ctx = TestContext::with_admin();
    let result = ctx.client.try_set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 0,
            vote_ttl_secs: VOTE_TTL,
        },
    );
    assert_qx_err(result, QuickexError::QuorumOutOfBounds);
}

#[test]
fn test_set_dispute_quorum_config_rejects_quorum_above_max() {
    let ctx = TestContext::with_admin();
    let result = ctx.client.try_set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: MAX_QUORUM + 1,
            vote_ttl_secs: VOTE_TTL,
        },
    );
    assert_qx_err(result, QuickexError::QuorumOutOfBounds);
}

#[test]
fn test_set_dispute_quorum_config_rejects_ttl_out_of_bounds() {
    let ctx = TestContext::with_admin();

    let too_short = ctx.client.try_set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: MIN_VOTE_TTL_SECS - 1,
        },
    );
    assert_qx_err(too_short, QuickexError::QuorumOutOfBounds);

    let too_long = ctx.client.try_set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: MAX_VOTE_TTL_SECS + 1,
        },
    );
    assert_qx_err(too_long, QuickexError::QuorumOutOfBounds);
}

#[test]
fn test_set_dispute_quorum_config_requires_admin() {
    let ctx = TestContext::with_admin();
    let not_admin = Address::generate(&ctx.env);
    let result = ctx.client.try_set_dispute_quorum_config(
        &not_admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: VOTE_TTL,
        },
    );
    assert_qx_err(result, QuickexError::InsufficientRole);
}

#[test]
fn test_get_dispute_quorum_config_defaults_when_never_set() {
    let ctx = TestContext::with_admin();
    let config = ctx.client.get_dispute_quorum_config();
    assert_eq!(config, DisputeQuorumConfig::default_config());
}

// ============================================================================
// AC5 (quorum reached): resolve_dispute_multi_sig succeeds with fresh votes
// ============================================================================

#[test]
fn test_quorum_reached_resolves_via_multi_sig() {
    let ctx = TestContext::with_admin();
    ctx.client.set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: VOTE_TTL,
        },
    );

    let (a1, a2, a3) = three_arbiters(&ctx);
    let recipient = Address::generate(&ctx.env);
    let commitment = open_multi_sig_dispute(
        &ctx,
        &ctx.alice.clone(),
        &[a1.clone(), a2.clone(), a3.clone()],
        2,
        5_000,
        b"quorum_reached",
    );

    ctx.client
        .vote_for_dispute(&a1, &commitment, &false, &0u64, &u64::MAX);
    ctx.client
        .vote_for_dispute(&a2, &commitment, &false, &0u64, &u64::MAX);

    ctx.client
        .resolve_dispute_multi_sig(&commitment, &recipient);

    assert_eq!(
        ctx.client.get_commitment_state(&commitment),
        Some(EscrowStatus::Spent)
    );
    assert_eq!(ctx.balance(&recipient), 5_000);
}

// ============================================================================
// AC2 (vote expiry) + AC3 (fallback on missed quorum)
// ============================================================================

#[test]
fn test_expired_vote_does_not_count_toward_quorum() {
    let ctx = TestContext::with_admin();
    ctx.client.set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: VOTE_TTL,
        },
    );

    let (a1, a2, _a3) = three_arbiters(&ctx);
    let commitment = open_multi_sig_dispute(
        &ctx,
        &ctx.alice.clone(),
        &[a1.clone(), a2.clone()],
        2,
        5_000,
        b"expired_vote",
    );

    // a1 votes immediately (expires at VOTE_TTL).
    ctx.client
        .vote_for_dispute(&a1, &commitment, &true, &0u64, &u64::MAX);

    // a2 votes partway through the window (expires at 3000 + VOTE_TTL).
    ctx.advance_time(3000);
    ctx.client
        .vote_for_dispute(&a2, &commitment, &true, &0u64, &u64::MAX);

    // Push past the deadline (disputed_at + VOTE_TTL) and past a1's expiry,
    // but before a2's expiry: only a2's vote should still be fresh.
    ctx.advance_time(700); // total elapsed: 3700 > VOTE_TTL (3600)

    let recipient = Address::generate(&ctx.env);
    // a1's expired vote must not count toward the 2-vote quorum.
    let result = ctx
        .client
        .try_resolve_dispute_multi_sig(&commitment, &recipient);
    assert_qx_err(result, QuickexError::InsufficientVotes);
}

#[test]
fn test_quorum_missed_with_expiry_falls_back_to_timeout_refund() {
    let ctx = TestContext::with_admin();
    ctx.client.set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: VOTE_TTL,
        },
    );

    let (a1, a2, _a3) = three_arbiters(&ctx);
    let owner = ctx.alice.clone();
    let commitment = open_multi_sig_dispute(
        &ctx,
        &owner,
        &[a1.clone(), a2.clone()],
        2,
        5_000,
        b"timeout",
    );

    // Only one of two required votes is ever cast.
    ctx.client
        .vote_for_dispute(&a1, &commitment, &true, &0u64, &u64::MAX);

    // Before the deadline: fallback is not yet available.
    let too_early = ctx.client.try_resolve_dispute_timeout(&commitment);
    assert_qx_err(too_early, QuickexError::InvalidDisputeState);

    // Push well past the deadline and past a1's own vote expiry.
    ctx.advance_time(VOTE_TTL + 1);

    let recipient = Address::generate(&ctx.env);
    let still_insufficient = ctx
        .client
        .try_resolve_dispute_multi_sig(&commitment, &recipient);
    assert_qx_err(still_insufficient, QuickexError::InsufficientVotes);

    ctx.client.resolve_dispute_timeout(&commitment);

    assert_eq!(
        ctx.client.get_commitment_state(&commitment),
        Some(EscrowStatus::Refunded)
    );
    assert_eq!(ctx.balance(&owner), 5_000);
}

#[test]
fn test_resolve_dispute_timeout_rejected_before_deadline() {
    let ctx = TestContext::with_admin();
    ctx.client.set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: VOTE_TTL,
        },
    );
    let (a1, a2, _a3) = three_arbiters(&ctx);
    let commitment =
        open_multi_sig_dispute(&ctx, &ctx.alice.clone(), &[a1, a2], 2, 5_000, b"too_early");

    let result = ctx.client.try_resolve_dispute_timeout(&commitment);
    assert_qx_err(result, QuickexError::InvalidDisputeState);
}

#[test]
fn test_resolve_dispute_timeout_rejected_when_quorum_still_reachable() {
    let ctx = TestContext::with_admin();
    ctx.client.set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: VOTE_TTL,
        },
    );
    let (a1, a2, _a3) = three_arbiters(&ctx);
    let commitment = open_multi_sig_dispute(
        &ctx,
        &ctx.alice.clone(),
        &[a1.clone(), a2.clone()],
        2,
        5_000,
        b"still_reachable",
    );

    // Both vote right at the deadline boundary so their votes stay fresh
    // for a while past it (expiry = voted_at + VOTE_TTL > deadline).
    ctx.advance_time(VOTE_TTL - 1);
    ctx.client
        .vote_for_dispute(&a1, &commitment, &true, &0u64, &u64::MAX);
    ctx.client
        .vote_for_dispute(&a2, &commitment, &true, &0u64, &u64::MAX);

    // Now past the deadline, but both votes are still fresh.
    ctx.advance_time(5);

    let result = ctx.client.try_resolve_dispute_timeout(&commitment);
    assert_qx_err(result, QuickexError::InvalidDisputeState);

    // The normal path still works.
    ctx.client
        .resolve_dispute_multi_sig(&commitment, &ctx.bob.clone());
    assert_eq!(
        ctx.client.get_commitment_state(&commitment),
        Some(EscrowStatus::Refunded)
    );
}

#[test]
fn test_vote_after_deadline_rejected() {
    let ctx = TestContext::with_admin();
    ctx.client.set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: VOTE_TTL,
        },
    );
    let (a1, a2, _a3) = three_arbiters(&ctx);
    let commitment = open_multi_sig_dispute(
        &ctx,
        &ctx.alice.clone(),
        &[a1.clone(), a2.clone()],
        2,
        5_000,
        b"vote_too_late",
    );

    ctx.advance_time(VOTE_TTL + 1);

    let result = ctx
        .client
        .try_vote_for_dispute(&a2, &commitment, &true, &0u64, &u64::MAX);
    assert_qx_err(result, QuickexError::InvalidDisputeState);
}

// ============================================================================
// AC4: mid-dispute reconfiguration cannot retroactively change an in-flight dispute
// ============================================================================

#[test]
fn test_mid_dispute_admin_reconfig_does_not_retroactively_change_open_dispute() {
    let ctx = TestContext::with_admin();
    ctx.client.set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: VOTE_TTL,
        },
    );

    let (a1, a2, a3) = three_arbiters(&ctx);
    let commitment = open_multi_sig_dispute(
        &ctx,
        &ctx.alice.clone(),
        &[a1.clone(), a2.clone(), a3.clone()],
        2,
        5_000,
        b"reconfig_mid_dispute",
    );

    // Admin tightens the global quorum after the dispute is already open.
    ctx.client.set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 3,
            vote_ttl_secs: VOTE_TTL,
        },
    );
    assert_eq!(ctx.client.get_dispute_quorum_config().quorum, 3);

    // The already-open dispute still only needs its originally-frozen
    // 2-vote quorum, not the newly configured 3.
    ctx.client
        .vote_for_dispute(&a1, &commitment, &true, &0u64, &u64::MAX);
    ctx.client
        .vote_for_dispute(&a2, &commitment, &true, &0u64, &u64::MAX);

    let recipient = Address::generate(&ctx.env);
    ctx.client
        .resolve_dispute_multi_sig(&commitment, &recipient);

    assert_eq!(
        ctx.client.get_commitment_state(&commitment),
        Some(EscrowStatus::Refunded)
    );
}

#[test]
fn test_mid_dispute_reconfig_does_not_shorten_an_open_disputes_deadline() {
    let ctx = TestContext::with_admin();
    ctx.client.set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: MAX_VOTE_TTL_SECS,
        },
    );

    let (a1, a2, _a3) = three_arbiters(&ctx);
    let commitment = open_multi_sig_dispute(
        &ctx,
        &ctx.alice.clone(),
        &[a1.clone(), a2.clone()],
        2,
        5_000,
        b"reconfig_deadline",
    );

    // Admin shortens the global vote TTL well after the dispute opened.
    ctx.client.set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: MIN_VOTE_TTL_SECS,
        },
    );

    // If the shorter TTL applied retroactively, the deadline would already
    // have passed by now; it must not have.
    ctx.advance_time(MIN_VOTE_TTL_SECS + 1);

    let result = ctx
        .client
        .try_vote_for_dispute(&a2, &commitment, &true, &0u64, &u64::MAX);
    assert!(
        result.is_ok(),
        "the dispute's original (longer) deadline must still be in effect"
    );
}
