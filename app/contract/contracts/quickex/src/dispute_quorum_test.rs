//! Tests for multi-sig dispute quorum: configurable quorum, vote expiry,
//! dispute deadline, fallback resolution, and mid-dispute reconfiguration safety.
//!
//! Acceptance Criteria addressed:
//! 1. Quorum size is configurable by admin within documented hard bounds.
//! 2. Votes carry an expiry; expired votes do not count toward quorum.
//! 3. A dispute that cannot reach quorum before a deadline has a documented
//!    fallback resolution path (admin_resolve_dispute_fallback).
//! 4. Changing quorum mid-dispute cannot retroactively resolve an in-flight dispute.
//! 5. Tests cover: quorum reached, quorum missed with expiry, mid-dispute reconfig.

use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, Bytes, BytesN, Env, Vec,
};

use crate::{
    errors::QuickexError,
    storage::{put_escrow, MAX_DISPUTE_DEADLINE_SECS, MAX_QUORUM_BOUND, MAX_VOTE_EXPIRY_SECS},
    types::{DisputeQuorumConfig, EscrowEntry, EscrowStatus},
    QuickexContract, QuickexContractClient,
};

// ---------------------------------------------------------------------------
// Shared setup helpers
// ---------------------------------------------------------------------------

fn setup<'a>() -> (Env, QuickexContractClient<'a>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

fn make_token(env: &Env) -> Address {
    env.register_stellar_asset_contract_v2(Address::generate(env))
        .address()
}

/// Create a Disputed escrow with N arbiters and the given threshold.
/// Returns (commitment, owner, arbiters, token).
fn setup_multi_sig_dispute<'a>(
    env: &Env,
    client: &QuickexContractClient<'a>,
    n_arbiters: u32,
    threshold: u32,
    dispute_deadline: u64,
) -> (BytesN<32>, Address, Vec<Address>, Address) {
    let token = make_token(env);
    let owner = Address::generate(env);
    let amount: i128 = 10_000;

    // Mint funds to the owner and into the contract
    token::StellarAssetClient::new(env, &token).mint(&owner, &amount);
    token::StellarAssetClient::new(env, &token).mint(&client.address, &amount);

    let mut arbiters: Vec<Address> = Vec::new(env);
    for _ in 0..n_arbiters {
        arbiters.push_back(Address::generate(env));
    }

    let commitment: BytesN<32> = BytesN::from_array(env, &[0xABu8; 32]);
    let commitment_bytes: Bytes = commitment.clone().into();

    let entry = EscrowEntry {
        token: token.clone(),
        amount_due: amount,
        amount_paid: amount,
        owner: owner.clone(),
        status: EscrowStatus::Disputed,
        created_at: env.ledger().timestamp(),
        expires_at: 0,
        arbiter: None,
        arbiters: arbiters.clone(),
        arbiter_threshold: threshold,
        dispute_deadline,
    };

    env.as_contract(&client.address, || {
        put_escrow(env, &commitment_bytes, &entry);
    });

    (commitment, owner, arbiters, token)
}

// ---------------------------------------------------------------------------
// AC1: Configurable quorum within hard bounds
// ---------------------------------------------------------------------------

#[test]
fn test_set_dispute_quorum_config_valid() {
    let (env, client, admin) = setup();
    let config = DisputeQuorumConfig {
        min_quorum: 2,
        max_quorum: 5,
        vote_expiry_secs: 86_400,      // 1 day
        dispute_deadline_secs: 604_800, // 7 days
    };
    client.set_dispute_quorum_config(&admin, &config);
    let stored = client.get_dispute_quorum_config();
    assert_eq!(stored.min_quorum, 2);
    assert_eq!(stored.max_quorum, 5);
    assert_eq!(stored.vote_expiry_secs, 86_400);
    assert_eq!(stored.dispute_deadline_secs, 604_800);
}

#[test]
fn test_set_dispute_quorum_config_rejects_zero_min_quorum() {
    let (env, client, admin) = setup();
    let config = DisputeQuorumConfig {
        min_quorum: 0, // invalid
        max_quorum: 5,
        vote_expiry_secs: 0,
        dispute_deadline_secs: 0,
    };
    let result = client.try_set_dispute_quorum_config(&admin, &config);
    assert!(matches!(result, Err(Ok(QuickexError::QuorumOutOfBounds))));
}

#[test]
fn test_set_dispute_quorum_config_rejects_max_above_hard_bound() {
    let (env, client, admin) = setup();
    let config = DisputeQuorumConfig {
        min_quorum: 1,
        max_quorum: MAX_QUORUM_BOUND + 1, // exceeds hard limit
        vote_expiry_secs: 0,
        dispute_deadline_secs: 0,
    };
    let result = client.try_set_dispute_quorum_config(&admin, &config);
    assert!(matches!(result, Err(Ok(QuickexError::QuorumOutOfBounds))));
}

#[test]
fn test_set_dispute_quorum_config_rejects_min_greater_than_max() {
    let (env, client, admin) = setup();
    let config = DisputeQuorumConfig {
        min_quorum: 5,
        max_quorum: 3, // min > max
        vote_expiry_secs: 0,
        dispute_deadline_secs: 0,
    };
    let result = client.try_set_dispute_quorum_config(&admin, &config);
    assert!(matches!(result, Err(Ok(QuickexError::QuorumOutOfBounds))));
}

#[test]
fn test_set_dispute_quorum_config_rejects_vote_expiry_above_hard_bound() {
    let (env, client, admin) = setup();
    let config = DisputeQuorumConfig {
        min_quorum: 1,
        max_quorum: 5,
        vote_expiry_secs: MAX_VOTE_EXPIRY_SECS + 1, // exceeds 30 days
        dispute_deadline_secs: 0,
    };
    let result = client.try_set_dispute_quorum_config(&admin, &config);
    assert!(matches!(result, Err(Ok(QuickexError::QuorumOutOfBounds))));
}

#[test]
fn test_set_dispute_quorum_config_rejects_deadline_above_hard_bound() {
    let (env, client, admin) = setup();
    let config = DisputeQuorumConfig {
        min_quorum: 1,
        max_quorum: 5,
        vote_expiry_secs: 0,
        dispute_deadline_secs: MAX_DISPUTE_DEADLINE_SECS + 1, // exceeds 90 days
    };
    let result = client.try_set_dispute_quorum_config(&admin, &config);
    assert!(matches!(result, Err(Ok(QuickexError::QuorumOutOfBounds))));
}

#[test]
fn test_non_admin_cannot_set_quorum_config() {
    let (env, client, _admin) = setup();
    let stranger = Address::generate(&env);
    let config = DisputeQuorumConfig {
        min_quorum: 1,
        max_quorum: 5,
        vote_expiry_secs: 0,
        dispute_deadline_secs: 0,
    };
    let result = client.try_set_dispute_quorum_config(&stranger, &config);
    assert!(matches!(result, Err(Ok(QuickexError::InsufficientRole))));
}

// ---------------------------------------------------------------------------
// AC1 + happy path: quorum reached — dispute resolves normally
// ---------------------------------------------------------------------------

#[test]
fn test_quorum_reached_resolves_dispute() {
    let (env, client, admin) = setup();

    // 2-of-3 quorum, no expiry, no deadline
    let (commitment, _owner, arbiters, _token) =
        setup_multi_sig_dispute(&env, &client, 3, 2, 0);

    let recipient = Address::generate(&env);

    // Two arbiters vote for recipient
    client.vote_for_dispute(&arbiters.get(0).unwrap(), &commitment, &false, &0, &u64::MAX);
    client.vote_for_dispute(&arbiters.get(1).unwrap(), &commitment, &false, &1, &u64::MAX);

    // Quorum reached — anyone can resolve
    client.resolve_dispute_multi_sig(&commitment, &recipient);

    let state = client.get_commitment_state(&commitment);
    assert_eq!(state, Some(EscrowStatus::Spent));
}

// ---------------------------------------------------------------------------
// AC2: Expired votes do not count toward quorum
// ---------------------------------------------------------------------------

#[test]
fn test_expired_votes_not_counted_toward_quorum() {
    let (env, client, admin) = setup();

    // Set 1-day vote expiry
    client.set_dispute_quorum_config(
        &admin,
        &DisputeQuorumConfig {
            min_quorum: 1,
            max_quorum: MAX_QUORUM_BOUND,
            vote_expiry_secs: 86_400, // 1 day
            dispute_deadline_secs: 0,
        },
    );

    // 2-of-3 quorum, no deadline
    let (commitment, _owner, arbiters, _token) =
        setup_multi_sig_dispute(&env, &client, 3, 2, 0);

    let recipient = Address::generate(&env);

    // Two arbiters vote at t=0
    client.vote_for_dispute(&arbiters.get(0).unwrap(), &commitment, &false, &0, &u64::MAX);
    client.vote_for_dispute(&arbiters.get(1).unwrap(), &commitment, &false, &1, &u64::MAX);

    // Fast-forward past the vote expiry (2 days later)
    env.ledger().set_timestamp(env.ledger().timestamp() + 2 * 86_400);

    // Votes have expired — resolve should fail with InsufficientVotes
    let result = client.try_resolve_dispute_multi_sig(&commitment, &recipient);
    assert!(matches!(result, Err(Ok(QuickexError::InsufficientVotes))));
}

#[test]
fn test_new_votes_after_expiry_restore_quorum() {
    let (env, client, admin) = setup();

    // 1-day vote expiry
    client.set_dispute_quorum_config(
        &admin,
        &DisputeQuorumConfig {
            min_quorum: 1,
            max_quorum: MAX_QUORUM_BOUND,
            vote_expiry_secs: 86_400,
            dispute_deadline_secs: 0,
        },
    );

    // 2-of-3 quorum, no deadline
    let (commitment, _owner, arbiters, _token) =
        setup_multi_sig_dispute(&env, &client, 3, 2, 0);

    let recipient = Address::generate(&env);

    // Only one arbiter votes initially
    client.vote_for_dispute(&arbiters.get(0).unwrap(), &commitment, &false, &0, &u64::MAX);

    // Fast-forward past expiry
    env.ledger().set_timestamp(env.ledger().timestamp() + 2 * 86_400);

    // Third arbiter votes — vote is fresh; arbiter 0's vote is expired
    // Still only 1 valid vote — should fail
    client.vote_for_dispute(&arbiters.get(2).unwrap(), &commitment, &false, &2, &u64::MAX);
    let result = client.try_resolve_dispute_multi_sig(&commitment, &recipient);
    assert!(matches!(result, Err(Ok(QuickexError::InsufficientVotes))));
}

// ---------------------------------------------------------------------------
// AC2: Voting after deadline is rejected
// ---------------------------------------------------------------------------

#[test]
fn test_vote_rejected_after_dispute_deadline() {
    let (env, client, _admin) = setup();

    let now = env.ledger().timestamp();
    let deadline = now + 1000;

    let (commitment, _owner, arbiters, _token) =
        setup_multi_sig_dispute(&env, &client, 3, 2, deadline);

    // Advance past the deadline
    env.ledger().set_timestamp(deadline + 1);

    let result =
        client.try_vote_for_dispute(&arbiters.get(0).unwrap(), &commitment, &false, &0, &u64::MAX);
    assert!(matches!(
        result,
        Err(Ok(QuickexError::DisputeDeadlineExpired))
    ));
}

// ---------------------------------------------------------------------------
// AC3: Fallback resolution after deadline
// ---------------------------------------------------------------------------

#[test]
fn test_admin_fallback_resolves_after_deadline_expired() {
    let (env, client, admin) = setup();

    let now = env.ledger().timestamp();
    let deadline = now + 1000;

    let (commitment, _owner, _arbiters, _token) =
        setup_multi_sig_dispute(&env, &client, 3, 2, deadline);

    let recipient = Address::generate(&env);

    // Advance past deadline without enough votes
    env.ledger().set_timestamp(deadline + 1);

    // Admin can now use fallback to resolve for owner (refund)
    client.admin_resolve_dispute_fallback(&admin, &commitment, &recipient, &true);

    let state = client.get_commitment_state(&commitment);
    assert_eq!(state, Some(EscrowStatus::Refunded));
}

#[test]
fn test_admin_fallback_blocked_while_quorum_still_reachable() {
    let (env, client, admin) = setup();

    // No deadline, no vote expiry — quorum is always reachable until votes cast
    let (commitment, _owner, arbiters, _token) =
        setup_multi_sig_dispute(&env, &client, 3, 2, 0);

    let recipient = Address::generate(&env);

    // Only 1 of 2 required votes cast — quorum still reachable
    client.vote_for_dispute(&arbiters.get(0).unwrap(), &commitment, &false, &0, &u64::MAX);

    let result =
        client.try_admin_resolve_dispute_fallback(&admin, &commitment, &recipient, &true);
    assert!(matches!(result, Err(Ok(QuickexError::InsufficientVotes))));
}

#[test]
fn test_admin_fallback_allowed_when_all_votes_expired() {
    let (env, client, admin) = setup();

    // 1-day vote expiry, no deadline
    client.set_dispute_quorum_config(
        &admin,
        &DisputeQuorumConfig {
            min_quorum: 1,
            max_quorum: MAX_QUORUM_BOUND,
            vote_expiry_secs: 86_400,
            dispute_deadline_secs: 0,
        },
    );

    // 2-of-3 quorum
    let (commitment, _owner, arbiters, _token) =
        setup_multi_sig_dispute(&env, &client, 3, 2, 0);

    let recipient = Address::generate(&env);

    // Only 1 arbiter votes — quorum requires 2
    client.vote_for_dispute(&arbiters.get(0).unwrap(), &commitment, &false, &0, &u64::MAX);

    // Fast-forward past vote expiry — that 1 vote is now expired, valid=0 < threshold=2
    env.ledger().set_timestamp(env.ledger().timestamp() + 2 * 86_400);

    // No deadline, but quorum is unreachable (valid < threshold) → fallback is allowed
    client.admin_resolve_dispute_fallback(&admin, &commitment, &recipient, &true);

    let state = client.get_commitment_state(&commitment);
    assert_eq!(state, Some(EscrowStatus::Refunded));
}

// ---------------------------------------------------------------------------
// AC4: Mid-dispute quorum reconfiguration cannot retroactively resolve
// ---------------------------------------------------------------------------

#[test]
fn test_mid_dispute_quorum_change_does_not_retroactively_resolve() {
    let (env, client, admin) = setup();

    // Start with 2-of-3 quorum required
    let (commitment, _owner, arbiters, _token) =
        setup_multi_sig_dispute(&env, &client, 3, 2, 0);

    let recipient = Address::generate(&env);

    // Only 1 arbiter votes
    client.vote_for_dispute(&arbiters.get(0).unwrap(), &commitment, &false, &0, &u64::MAX);

    // Admin lowers global quorum bounds — but per-escrow threshold is FIXED at 2
    client.set_dispute_quorum_config(
        &admin,
        &DisputeQuorumConfig {
            min_quorum: 1,
            max_quorum: 1, // lowered
            vote_expiry_secs: 0,
            dispute_deadline_secs: 0,
        },
    );

    // Should still fail — per-escrow threshold of 2 is authoritative
    let result = client.try_resolve_dispute_multi_sig(&commitment, &recipient);
    assert!(matches!(result, Err(Ok(QuickexError::InsufficientVotes))));

    // Second vote cast — now 2-of-3 threshold met
    client.vote_for_dispute(&arbiters.get(1).unwrap(), &commitment, &false, &1, &u64::MAX);
    client.resolve_dispute_multi_sig(&commitment, &recipient);

    let state = client.get_commitment_state(&commitment);
    assert_eq!(state, Some(EscrowStatus::Spent));
}
