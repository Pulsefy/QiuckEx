//! Tests for the public `deposit_multi_sig` entrypoint (issue #1012).
//!
//! `deposit_multi_sig` is the only path that can put an escrow into multi-sig
//! mode (`arbiter_threshold > 0`), and therefore the only way for a caller to
//! reach `vote_for_dispute`, `resolve_dispute_multi_sig`, and
//! `resolve_dispute_timeout`. Before it existed, every escrow was created with
//! an empty `arbiters` vec and a zero threshold, so that whole surface was
//! unreachable without rewriting contract storage by hand.
//!
//! Everything here goes through the public contract client — no test writes
//! `EscrowEntry.arbiters` / `arbiter_threshold` directly. Reading the stored
//! entry back (to assert what was persisted) uses `storage::get_escrow` inside
//! `env.as_contract`, matching the rest of the suite.

use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, Bytes, BytesN, Env, Vec,
};

use crate::{
    assert_helpers::{assert_escrow_disputed, assert_escrow_spent, assert_qx_err},
    dispute_quorum::{DisputeQuorumConfig, MAX_ARBITERS, MIN_VOTE_TTL_SECS},
    errors::QuickexError,
    storage::get_escrow,
    test_context::TestContext,
    types::{EscrowStatus, PerAssetFeeConfig, Role},
    PauseFlag,
};

const AMOUNT: i128 = 1_000_000;
const SALT: &[u8] = b"multi_sig_deposit_salt";
/// Distinct from `TestContext::TEST_DEPOSIT_NONCE` so idempotency tests can
/// re-submit the same payload without tripping the replay guard first.
const FRESH_NONCE: u64 = 42;
const NEVER: u64 = u64::MAX;

fn arbiters_vec(env: &Env, arbiters: &[Address]) -> Vec<Address> {
    let mut set = Vec::new(env);
    for arbiter in arbiters {
        set.push_back(arbiter.clone());
    }
    set
}

/// `count` fresh generated addresses — used for the `MAX_ARBITERS` bound tests.
fn generated_arbiters(env: &Env, count: u32) -> Vec<Address> {
    let mut set = Vec::new(env);
    for _ in 0..count {
        set.push_back(Address::generate(env));
    }
    set
}

/// Read the persisted entry for `commitment` back out of contract storage.
fn stored_entry(
    env: &Env,
    contract: &Address,
    commitment: &BytesN<32>,
) -> crate::types::EscrowEntry {
    let key: Bytes = commitment.clone().into();
    env.as_contract(contract, || get_escrow(env, &key).expect("escrow exists"))
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

#[test]
fn deposit_multi_sig_persists_arbiter_set_and_threshold() {
    let ctx = TestContext::new();
    let owner = ctx.alice.clone();
    let arbiters = [
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
    ];

    let commitment = ctx.deposit_with_arbiters(&owner, AMOUNT, SALT, 0, &arbiters, 2);

    let entry = stored_entry(&ctx.env, &ctx.client.address, &commitment);

    assert_eq!(entry.status, EscrowStatus::Pending);
    assert_eq!(entry.owner, owner);
    assert_eq!(entry.amount_due, AMOUNT);
    assert_eq!(entry.amount_paid, AMOUNT);
    // The single-arbiter field stays empty: a multi-sig escrow deliberately
    // names no one arbiter, which is also why it needs its own dispute event.
    assert_eq!(entry.arbiter, None);
    assert_eq!(entry.arbiter_threshold, 2);
    assert_eq!(entry.arbiters.len(), 3);
    assert_eq!(entry.arbiters.get(0), Some(arbiters[0].clone()));
    assert_eq!(entry.arbiters.get(1), Some(arbiters[1].clone()));
    assert_eq!(entry.arbiters.get(2), Some(arbiters[2].clone()));
    // Funds actually moved.
    assert_eq!(ctx.balance(&ctx.client.address), AMOUNT);
}

#[test]
fn deposit_multi_sig_derivable_id_matches_and_binds_the_arbiter_set() {
    let ctx = TestContext::new();
    let owner = ctx.alice.clone();
    let arbiters = [
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
    ];
    let salt = ctx.salt(SALT);

    let commitment = ctx.deposit_with_arbiters(&owner, AMOUNT, SALT, 0, &arbiters, 2);

    // The public derivation resolves to the commitment the deposit returned,
    // proving the derivation is observable on-chain for multi-sig payloads.
    let derived_id = ctx.client.derive_escrow_id_multi_sig(
        &ctx.token,
        &AMOUNT,
        &owner,
        &salt,
        &0,
        &arbiters_vec(&ctx.env, &arbiters),
        &2,
    );
    assert_eq!(
        ctx.client.get_escrow_id_commitment(&derived_id),
        Some(commitment.clone())
    );
    // Deterministic: same input, same id.
    assert_eq!(
        ctx.client.derive_escrow_id_multi_sig(
            &ctx.token,
            &AMOUNT,
            &owner,
            &salt,
            &0,
            &arbiters_vec(&ctx.env, &arbiters),
            &2,
        ),
        ctx.client.derive_escrow_id_multi_sig(
            &ctx.token,
            &AMOUNT,
            &owner,
            &salt,
            &0,
            &arbiters_vec(&ctx.env, &arbiters),
            &2,
        )
    );

    // Every arbiter-set component is bound into the id: without this, a
    // re-submission with different arbiters would resolve to the earlier
    // escrow's commitment and silently reuse it.
    let different_arbiters = [
        arbiters[0].clone(),
        arbiters[1].clone(),
        Address::generate(&ctx.env),
    ];
    let other_set_id = ctx.client.derive_escrow_id_multi_sig(
        &ctx.token,
        &AMOUNT,
        &owner,
        &salt,
        &0,
        &arbiters_vec(&ctx.env, &different_arbiters),
        &2,
    );
    assert_ne!(other_set_id, commitment.clone());

    // Threshold is bound too.
    assert_ne!(
        ctx.client.derive_escrow_id_multi_sig(
            &ctx.token,
            &AMOUNT,
            &owner,
            &salt,
            &0,
            &arbiters_vec(&ctx.env, &arbiters),
            &3,
        ),
        commitment.clone()
    );

    // Order matters — the set is stored as given, so the id is order-sensitive.
    let reordered = [
        arbiters[1].clone(),
        arbiters[0].clone(),
        arbiters[2].clone(),
    ];
    assert_ne!(
        ctx.client.derive_escrow_id_multi_sig(
            &ctx.token,
            &AMOUNT,
            &owner,
            &salt,
            &0,
            &arbiters_vec(&ctx.env, &reordered),
            &2,
        ),
        commitment.clone()
    );

    // And a multi-sig id never collides with the single-sig id for the same
    // (token, amount, owner, salt, timeout) payload.
    assert_ne!(
        ctx.client
            .derive_escrow_id(&ctx.token, &AMOUNT, &owner, &salt, &0, &None),
        commitment
    );
}

#[test]
fn deposit_multi_sig_rejects_invalid_arbiter_sets() {
    let ctx = TestContext::new();
    let owner = ctx.alice.clone();
    let a1 = Address::generate(&ctx.env);
    let a2 = Address::generate(&ctx.env);
    let salt = ctx.salt(SALT);

    // Empty set: multi-sig mode with nobody to vote.
    assert_qx_err(
        ctx.client.try_deposit_multi_sig(
            &ctx.token,
            &AMOUNT,
            &owner,
            &salt,
            &0,
            &arbiters_vec(&ctx.env, &[]),
            &1,
            &FRESH_NONCE,
            &NEVER,
        ),
        QuickexError::QuorumOutOfBounds,
    );

    // Threshold 0 would silently leave the escrow in single-arbiter mode with
    // no arbiter at all — the exact dead escrow this issue is about.
    assert_qx_err(
        ctx.client.try_deposit_multi_sig(
            &ctx.token,
            &AMOUNT,
            &owner,
            &salt,
            &0,
            &arbiters_vec(&ctx.env, core::slice::from_ref(&a1)),
            &0,
            &FRESH_NONCE,
            &NEVER,
        ),
        QuickexError::QuorumOutOfBounds,
    );

    // Threshold above the set size can never be met.
    assert_qx_err(
        ctx.client.try_deposit_multi_sig(
            &ctx.token,
            &AMOUNT,
            &owner,
            &salt,
            &0,
            &arbiters_vec(&ctx.env, &[a1.clone(), a2.clone()]),
            &3,
            &FRESH_NONCE,
            &NEVER,
        ),
        QuickexError::QuorumOutOfBounds,
    );

    // Duplicate arbiter: one address voting once must not be counted twice
    // toward the quorum.
    assert_qx_err(
        ctx.client.try_deposit_multi_sig(
            &ctx.token,
            &AMOUNT,
            &owner,
            &salt,
            &0,
            &arbiters_vec(&ctx.env, &[a1.clone(), a1.clone()]),
            &1,
            &FRESH_NONCE,
            &NEVER,
        ),
        QuickexError::QuorumOutOfBounds,
    );

    // Oversized set (MAX_ARBITERS + 1).
    let too_many = generated_arbiters(&ctx.env, MAX_ARBITERS + 1);
    assert_qx_err(
        ctx.client.try_deposit_multi_sig(
            &ctx.token,
            &AMOUNT,
            &owner,
            &salt,
            &0,
            &too_many,
            &1,
            &FRESH_NONCE,
            &NEVER,
        ),
        QuickexError::QuorumOutOfBounds,
    );

    // Largest legal set is accepted.
    let at_max = generated_arbiters(&ctx.env, MAX_ARBITERS);
    token::StellarAssetClient::new(&ctx.env, &ctx.token).mint(&owner, &AMOUNT);
    let _at_max_commitment: BytesN<32> = ctx.client.deposit_multi_sig(
        &ctx.token,
        &AMOUNT,
        &owner,
        &ctx.salt(b"at_max_arbiters"),
        &0,
        &at_max,
        &MAX_ARBITERS,
        &FRESH_NONCE,
        &NEVER,
    );

    // No escrow was written by any of the rejected calls.
    assert_eq!(ctx.balance(&ctx.client.address), AMOUNT);
}

#[test]
fn deposit_multi_sig_rejects_zero_amount() {
    let ctx = TestContext::new();
    let arbiters = [Address::generate(&ctx.env), Address::generate(&ctx.env)];

    assert_qx_err(
        ctx.client.try_deposit_multi_sig(
            &ctx.token,
            &0,
            &ctx.alice,
            &ctx.salt(SALT),
            &0,
            &arbiters_vec(&ctx.env, &arbiters),
            &1,
            &FRESH_NONCE,
            &NEVER,
        ),
        QuickexError::InvalidAmount,
    );
}

#[test]
fn deposit_multi_sig_is_idempotent_for_an_identical_payload() {
    let ctx = TestContext::new();
    let owner = ctx.alice.clone();
    let arbiters = [Address::generate(&ctx.env), Address::generate(&ctx.env)];

    let first = ctx.deposit_with_arbiters(&owner, AMOUNT, SALT, 0, &arbiters, 2);
    // Same payload, fresh nonce: resolves to the same commitment rather than
    // creating a second escrow or moving funds again.
    let second = ctx.client.deposit_multi_sig(
        &ctx.token,
        &AMOUNT,
        &owner,
        &ctx.salt(SALT),
        &0,
        &arbiters_vec(&ctx.env, &arbiters),
        &2,
        &FRESH_NONCE,
        &NEVER,
    );

    assert_eq!(second, first);
    assert_eq!(ctx.balance(&ctx.client.address), AMOUNT);
}

#[test]
fn deposit_multi_sig_rejects_conflicting_amount_for_same_owner_and_salt() {
    let ctx = TestContext::new();
    let owner = ctx.alice.clone();
    let first_arbiters = [Address::generate(&ctx.env), Address::generate(&ctx.env)];
    let second_arbiters = [Address::generate(&ctx.env), Address::generate(&ctx.env)];

    let first = ctx.deposit_with_arbiters(&owner, AMOUNT, SALT, 0, &first_arbiters, 2);
    // The amount commitment is still owner+amount+salt scoped, so a different
    // arbiter set on the same amount cannot open a second escrow — the id
    // differs but the commitment collides.
    assert_qx_err(
        ctx.client.try_deposit_multi_sig(
            &ctx.token,
            &AMOUNT,
            &owner,
            &ctx.salt(SALT),
            &0,
            &arbiters_vec(&ctx.env, &second_arbiters),
            &2,
            &FRESH_NONCE,
            &NEVER,
        ),
        QuickexError::CommitmentAlreadyExists,
    );
    assert_eq!(
        ctx.client.get_commitment_state(&first),
        Some(EscrowStatus::Pending)
    );
}

#[test]
fn deposit_multi_sig_nonce_is_domain_separated_from_deposit() {
    let ctx = TestContext::new();
    let owner = ctx.alice.clone();
    let arbiters = [Address::generate(&ctx.env), Address::generate(&ctx.env)];
    let salt = ctx.salt(SALT);

    // Same owner, same nonce value (0) on both deposit variants: allowed,
    // because the consumed-nonce key includes the action type.
    token::StellarAssetClient::new(&ctx.env, &ctx.token).mint(&owner, &(AMOUNT * 2));
    let single = ctx
        .client
        .deposit(&ctx.token, &AMOUNT, &owner, &salt, &0, &None, &0, &NEVER);
    let multi = ctx.client.deposit_multi_sig(
        &ctx.token,
        &AMOUNT,
        &owner,
        &ctx.salt(b"multi_sig_salt"),
        &0,
        &arbiters_vec(&ctx.env, &arbiters),
        &1,
        &0,
        &NEVER,
    );
    assert_ne!(single, multi);

    // But each variant's own nonce is still single-use, so a signature minted
    // for one cannot be replayed on it.
    assert_qx_err(
        ctx.client.try_deposit_multi_sig(
            &ctx.token,
            &AMOUNT,
            &owner,
            &ctx.salt(b"replay_attempt"),
            &0,
            &arbiters_vec(&ctx.env, &arbiters),
            &1,
            &0,
            &NEVER,
        ),
        QuickexError::NonceAlreadyUsed,
    );
}

#[test]
fn deposit_multi_sig_honours_the_deposit_pause_flag() {
    let ctx = TestContext::with_admin();
    let arbiters = [Address::generate(&ctx.env), Address::generate(&ctx.env)];
    ctx.client
        .pause_features(&ctx.admin, &(PauseFlag::Deposit as u64), &0);

    assert_qx_err(
        ctx.client.try_deposit_multi_sig(
            &ctx.token,
            &AMOUNT,
            &ctx.alice,
            &ctx.salt(SALT),
            &0,
            &arbiters_vec(&ctx.env, &arbiters),
            &1,
            &FRESH_NONCE,
            &NEVER,
        ),
        QuickexError::OperationPaused,
    );
}

// ---------------------------------------------------------------------------
// End-to-end dispute lifecycle
// ---------------------------------------------------------------------------

#[test]
fn multi_sig_dispute_resolves_to_recipient_once_quorum_is_reached() {
    let ctx = TestContext::new();
    let owner = ctx.alice.clone();
    let recipient = ctx.bob.clone();
    let arbiters = [
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
    ];
    // Default policy is a quorum of 2, so 2-of-3 resolves without any admin
    // configuration.
    let commitment = ctx.deposit_with_arbiters(&owner, AMOUNT, SALT, 0, &arbiters, 2);

    ctx.client.dispute(&commitment);
    assert_escrow_disputed(&ctx.client, &commitment);

    // Quorum not met yet.
    assert_qx_err(
        ctx.client
            .try_resolve_dispute_multi_sig(&commitment, &recipient),
        QuickexError::InsufficientVotes,
    );

    // A non-arbiter cannot vote.
    assert_qx_err(
        ctx.client
            .try_vote_for_dispute(&ctx.bob, &commitment, &false, &0, &NEVER),
        QuickexError::NotAnArbiter,
    );

    for arbiter in arbiters.iter().take(2) {
        ctx.client
            .vote_for_dispute(arbiter, &commitment, &false, &0, &NEVER);
    }

    ctx.client
        .resolve_dispute_multi_sig(&commitment, &recipient);

    assert_escrow_spent(&ctx.client, &commitment);
    assert_eq!(ctx.balance(&recipient), AMOUNT);
}

#[test]
fn multi_sig_dispute_refunds_owner_when_majority_votes_for_owner() {
    let ctx = TestContext::new();
    let owner = ctx.alice.clone();
    let recipient = ctx.bob.clone();
    let arbiters = [
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
    ];
    let commitment = ctx.deposit_with_arbiters(&owner, AMOUNT, SALT, 0, &arbiters, 2);

    ctx.client.dispute(&commitment);
    for arbiter in arbiters.iter().take(2) {
        ctx.client
            .vote_for_dispute(arbiter, &commitment, &true, &0, &NEVER);
    }

    ctx.client
        .resolve_dispute_multi_sig(&commitment, &recipient);

    assert_eq!(
        ctx.client.get_commitment_state(&commitment),
        Some(EscrowStatus::Refunded)
    );
    assert_eq!(ctx.balance(&owner), AMOUNT);
    assert_eq!(ctx.balance(&recipient), 0);
}

#[test]
fn resolve_dispute_cannot_bypass_the_multi_sig_threshold() {
    let ctx = TestContext::with_admin();
    let owner = ctx.alice.clone();
    let recipient = ctx.bob.clone();
    let arbiter = Address::generate(&ctx.env);
    let commitment =
        ctx.deposit_with_arbiters(&owner, AMOUNT, SALT, 0, core::slice::from_ref(&arbiter), 1);
    ctx.client.dispute(&commitment);

    // Even a global Arbiter role holder — the identity that *would* be
    // allowed to resolve any single-arbiter escrow — cannot resolve a
    // 1-of-1 multi-sig escrow on its own.
    ctx.client.grant_role(&ctx.admin, &ctx.bob, &Role::Arbiter);
    assert_qx_err(
        ctx.client
            .try_resolve_dispute(&ctx.bob, &commitment, &false, &recipient, &0, &NEVER),
        QuickexError::InvalidDisputeState,
    );

    // Quorum still governs it.
    ctx.client
        .vote_for_dispute(&arbiter, &commitment, &false, &0, &NEVER);
    ctx.client
        .resolve_dispute_multi_sig(&commitment, &recipient);
    assert_escrow_spent(&ctx.client, &commitment);
}

#[test]
fn single_sig_escrow_still_cannot_vote() {
    let ctx = TestContext::new();
    let commitment = ctx.deposit_with_arbiter(&ctx.alice, AMOUNT, SALT, 0);
    ctx.client.dispute(&commitment);

    // Unchanged single-arbiter behaviour: the escrow has no arbiter set, so
    // the multi-sig voting path rejects it.
    assert_qx_err(
        ctx.client
            .try_vote_for_dispute(&ctx.arbiter, &commitment, &true, &0, &NEVER),
        QuickexError::NoArbiter,
    );
}

#[test]
fn multi_sig_dispute_times_out_back_to_the_owner() {
    let ctx = TestContext::with_admin();
    let owner = ctx.alice.clone();
    let recipient = ctx.bob.clone();
    let arbiters = [
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
    ];

    // Shortest legal voting window keeps the test quick.
    ctx.client.set_dispute_quorum_config(
        &ctx.admin,
        &DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: MIN_VOTE_TTL_SECS,
        },
    );

    let commitment = ctx.deposit_with_arbiters(&owner, AMOUNT, SALT, 0, &arbiters, 2);
    ctx.client.dispute(&commitment);

    // One vote short of quorum, past the frozen deadline.
    ctx.client
        .vote_for_dispute(&arbiters[0], &commitment, &false, &0, &NEVER);
    ctx.env.ledger().set_timestamp(MIN_VOTE_TTL_SECS + 1);

    // Still not resolvable by quorum...
    assert_qx_err(
        ctx.client
            .try_resolve_dispute_multi_sig(&commitment, &recipient),
        QuickexError::InsufficientVotes,
    );
    // ...but the fail-closed timeout path releases the funds to the owner.
    ctx.client.resolve_dispute_timeout(&commitment);
    assert_eq!(
        ctx.client.get_commitment_state(&commitment),
        Some(EscrowStatus::Refunded)
    );
    assert_eq!(ctx.balance(&owner), AMOUNT);
}

// ---------------------------------------------------------------------------
// Arbiter fee split on multi-sig resolution (issue #1005)
// ---------------------------------------------------------------------------

/// Mirrors the single-arbiter split in
/// `fee_router_test::test_fee_router_dispute_with_optional_arbiter_split`:
/// 10% of `amount` is fee, 20% of that fee is the arbiter pool.
///
/// - `amount`         = 1_000
/// - total fee        = 100
/// - arbiter pool     = 20
/// - per winner       = 20 / winners, floor
/// - collector        = 100 − (per winner × winners)
/// - recipient net    = 900
const FEE_AMOUNT: i128 = 1_000;
const FEE_BPS: u32 = 1_000; // 10% of the escrow is the platform fee
const ARBITER_BPS: u32 = 2_000; // 20% of the fee is the arbiter pool

/// Configure a collector plus a per-asset fee with a live `arbiter_bps` split
/// for the test context's token.
fn configure_arbiter_fee(ctx: &TestContext, collector: &Address) {
    ctx.client.set_platform_wallet(&ctx.admin, collector);
    ctx.client.set_per_asset_fee(
        &ctx.admin,
        &ctx.token,
        &PerAssetFeeConfig {
            fee_bps: FEE_BPS,
            arbiter_bps: ARBITER_BPS,
        },
    );
}

#[test]
fn multi_sig_dispute_pays_arbiter_fee_split_to_winning_voters() {
    let ctx = TestContext::with_admin();
    let owner = ctx.alice.clone();
    let recipient = ctx.bob.clone();
    let collector = Address::generate(&ctx.env);
    let arbiters = [
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
    ];
    configure_arbiter_fee(&ctx, &collector);

    let commitment = ctx.deposit_with_arbiters(&owner, FEE_AMOUNT, SALT, 0, &arbiters, 2);

    ctx.client.dispute(&commitment);
    // Default quorum is 2, so two of the three votes for the recipient settle it.
    for arbiter in arbiters.iter().take(2) {
        ctx.client
            .vote_for_dispute(arbiter, &commitment, &false, &0, &NEVER);
    }
    ctx.client
        .resolve_dispute_multi_sig(&commitment, &recipient);

    assert_escrow_spent(&ctx.client, &commitment);

    // The arbiter pool (20) is split equally across the two arbiters whose
    // fresh votes decided the outcome — 10 each, not 0 as before the fix and
    // not 20 to a single arbitrary winner.
    assert_eq!(ctx.balance(&arbiters[0]), 10);
    assert_eq!(ctx.balance(&arbiters[1]), 10);
    // The third arbiter did not vote for the winning side, so it is not owed.
    assert_eq!(ctx.balance(&arbiters[2]), 0);

    // Recipient 900, collector 100 − 20 = 80.
    assert_eq!(ctx.balance(&recipient), 900);
    assert_eq!(ctx.balance(&collector), 80);

    // Nothing is stranded or minted: the three destinations sum to the gross
    // amount and the contract keeps none of it.
    let paid = ctx.balance(&recipient)
        + ctx.balance(&collector)
        + ctx.balance(&arbiters[0])
        + ctx.balance(&arbiters[1])
        + ctx.balance(&arbiters[2]);
    assert_eq!(paid, FEE_AMOUNT);
    assert_eq!(ctx.balance(&ctx.client.address), 0);
}

#[test]
fn multi_sig_arbiter_fee_split_leaves_the_rounding_remainder_with_the_platform() {
    let ctx = TestContext::with_admin();
    let owner = ctx.alice.clone();
    let recipient = ctx.bob.clone();
    let collector = Address::generate(&ctx.env);
    let arbiters = [
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
    ];
    configure_arbiter_fee(&ctx, &collector);

    let commitment = ctx.deposit_with_arbiters(&owner, FEE_AMOUNT, SALT, 0, &arbiters, 2);

    // All three vote for the recipient, so the pool of 20 divides 3 ways:
    // 6 each with 2 left over. The remainder stays with the platform rather
    // than being rounded up onto the arbiters.
    ctx.client.dispute(&commitment);
    for arbiter in arbiters.iter() {
        ctx.client
            .vote_for_dispute(arbiter, &commitment, &false, &0, &NEVER);
    }
    ctx.client
        .resolve_dispute_multi_sig(&commitment, &recipient);

    for arbiter in arbiters.iter() {
        assert_eq!(ctx.balance(arbiter), 6);
    }
    assert_eq!(ctx.balance(&collector), 100 - 18);
    assert_eq!(ctx.balance(&recipient), 900);

    let paid = ctx.balance(&recipient)
        + ctx.balance(&collector)
        + arbiters.iter().map(|a| ctx.balance(a)).sum::<i128>();
    assert_eq!(paid, FEE_AMOUNT);
}

#[test]
fn multi_sig_arbiter_fee_excludes_arbiters_that_voted_for_the_owner() {
    let ctx = TestContext::with_admin();
    let owner = ctx.alice.clone();
    let recipient = ctx.bob.clone();
    let collector = Address::generate(&ctx.env);
    let arbiters = [
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
    ];
    configure_arbiter_fee(&ctx, &collector);

    let commitment = ctx.deposit_with_arbiters(&owner, FEE_AMOUNT, SALT, 0, &arbiters, 2);

    // 2-1 for the recipient, so it resolves to Spent. The split must follow the
    // votes that won, not merely the escrow's whole arbiter set.
    ctx.client.dispute(&commitment);
    ctx.client
        .vote_for_dispute(&arbiters[0], &commitment, &false, &0, &NEVER);
    ctx.client
        .vote_for_dispute(&arbiters[1], &commitment, &false, &0, &NEVER);
    ctx.client
        .vote_for_dispute(&arbiters[2], &commitment, &true, &0, &NEVER);
    ctx.client
        .resolve_dispute_multi_sig(&commitment, &recipient);

    assert_escrow_spent(&ctx.client, &commitment);
    assert_eq!(ctx.balance(&arbiters[0]), 10);
    assert_eq!(ctx.balance(&arbiters[1]), 10);
    // Voted for the losing side, and never voted at all: neither is owed.
    assert_eq!(ctx.balance(&arbiters[2]), 0);
    assert_eq!(ctx.balance(&arbiters[3]), 0);
    assert_eq!(ctx.balance(&collector), 80);
    assert_eq!(ctx.balance(&recipient), 900);
}

#[test]
fn multi_sig_owner_refund_charges_no_arbiter_fee() {
    let ctx = TestContext::with_admin();
    let owner = ctx.alice.clone();
    let recipient = ctx.bob.clone();
    let collector = Address::generate(&ctx.env);
    let arbiters = [
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
        Address::generate(&ctx.env),
    ];
    // A live arbiter_bps that a refund must still ignore: resolving for the
    // owner is a refund, so no fee of any kind is charged.
    configure_arbiter_fee(&ctx, &collector);

    let commitment = ctx.deposit_with_arbiters(&owner, FEE_AMOUNT, SALT, 0, &arbiters, 2);

    ctx.client.dispute(&commitment);
    for arbiter in arbiters.iter().take(2) {
        ctx.client
            .vote_for_dispute(arbiter, &commitment, &true, &0, &NEVER);
    }
    ctx.client
        .resolve_dispute_multi_sig(&commitment, &recipient);

    assert_eq!(
        ctx.client.get_commitment_state(&commitment),
        Some(EscrowStatus::Refunded)
    );
    assert_eq!(ctx.balance(&owner), FEE_AMOUNT);
    assert_eq!(ctx.balance(&recipient), 0);
    for arbiter in arbiters.iter() {
        assert_eq!(ctx.balance(arbiter), 0);
    }
    assert_eq!(ctx.balance(&collector), 0);
}
