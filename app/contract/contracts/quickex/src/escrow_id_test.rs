//! Tests for deterministic escrow-id derivation (Issue #304).
//!
//! These tests validate the four invariants documented in
//! [`crate::escrow_id`]:
//!
//! 1. **Determinism** — identical inputs always yield the same id.
//! 2. **Collision resistance** — changing any single field changes the id.
//! 3. **Domain separation** — the escrow id cannot collide with a
//!    commitment hash over the same `(owner, amount, salt)` tuple.
//! 4. **Unambiguous boundaries** — length-prefixing prevents two distinct
//!    parameter tuples from producing the same serialized payload.
//!
//! It also verifies the idempotent-deposit behavior required by the
//! acceptance criteria: "Duplicate creates are rejected or return existing
//! escrow deterministically."

use crate::{QuickexContract, QuickexContractClient};
use soroban_sdk::{
    testutils::Address as _,
    token::{StellarAssetClient, TokenClient},
    Address, Bytes, Env,
};

extern crate std;

fn setup<'a>() -> (Env, QuickexContractClient<'a>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    (env, client)
}

/// Register a SAC test token and return (token_address, admin).
fn register_token<'a>(env: &'a Env) -> (Address, StellarAssetClient<'a>, TokenClient<'a>) {
    let admin = Address::generate(env);
    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = sac.address();
    let mint_client = StellarAssetClient::new(env, &token_address);
    let token_client = TokenClient::new(env, &token_address);
    (token_address, mint_client, token_client)
}

// ============================================================================
// Invariant 1: Determinism — same inputs yield the same escrow_id.
// ============================================================================

#[test]
fn test_escrow_id_deterministic() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner = Address::generate(&env);
    let arbiter = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"canonical_salt");

    let id1 = client.derive_escrow_id(
        &token,
        &1_000i128,
        &owner,
        &salt,
        &3600u64,
        &Some(arbiter.clone()),
    );
    let id2 = client.derive_escrow_id(&token, &1_000i128, &owner, &salt, &3600u64, &Some(arbiter));

    assert_eq!(id1, id2);
    assert_eq!(id1.len(), 32);
}

#[test]
fn test_escrow_id_stable_across_many_calls() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"repeat");

    let mut ids = std::vec::Vec::new();
    for _ in 0..16 {
        ids.push(client.derive_escrow_id(&token, &42i128, &owner, &salt, &0u64, &None));
    }
    for i in 1..ids.len() {
        assert_eq!(ids[0], ids[i]);
    }
}

// ============================================================================
// Invariant 2: Collision resistance — any input change flips the id.
// ============================================================================

#[test]
fn test_escrow_id_changes_with_amount() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"amt");

    let id_a = client.derive_escrow_id(&token, &100i128, &owner, &salt, &0u64, &None);
    let id_b = client.derive_escrow_id(&token, &101i128, &owner, &salt, &0u64, &None);
    assert_ne!(id_a, id_b);
}

#[test]
fn test_escrow_id_changes_with_token() {
    let (env, client) = setup();
    let token_a = Address::generate(&env);
    let token_b = Address::generate(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"tok");

    let id_a = client.derive_escrow_id(&token_a, &100i128, &owner, &salt, &0u64, &None);
    let id_b = client.derive_escrow_id(&token_b, &100i128, &owner, &salt, &0u64, &None);
    assert_ne!(id_a, id_b);
}

#[test]
fn test_escrow_id_changes_with_owner() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner_a = Address::generate(&env);
    let owner_b = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"own");

    let id_a = client.derive_escrow_id(&token, &100i128, &owner_a, &salt, &0u64, &None);
    let id_b = client.derive_escrow_id(&token, &100i128, &owner_b, &salt, &0u64, &None);
    assert_ne!(id_a, id_b);
}

#[test]
fn test_escrow_id_changes_with_salt() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner = Address::generate(&env);

    let id_a = client.derive_escrow_id(
        &token,
        &100i128,
        &owner,
        &Bytes::from_slice(&env, b"alpha"),
        &0u64,
        &None,
    );
    let id_b = client.derive_escrow_id(
        &token,
        &100i128,
        &owner,
        &Bytes::from_slice(&env, b"beta"),
        &0u64,
        &None,
    );
    assert_ne!(id_a, id_b);
}

#[test]
fn test_escrow_id_changes_with_timeout() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"to");

    let id_a = client.derive_escrow_id(&token, &100i128, &owner, &salt, &0u64, &None);
    let id_b = client.derive_escrow_id(&token, &100i128, &owner, &salt, &3600u64, &None);
    assert_ne!(id_a, id_b);
}

#[test]
fn test_escrow_id_changes_with_arbiter_presence() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner = Address::generate(&env);
    let arbiter = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"arb");

    let id_none = client.derive_escrow_id(&token, &100i128, &owner, &salt, &0u64, &None);
    let id_some = client.derive_escrow_id(&token, &100i128, &owner, &salt, &0u64, &Some(arbiter));
    assert_ne!(id_none, id_some);
}

#[test]
fn test_escrow_id_changes_with_arbiter_identity() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner = Address::generate(&env);
    let arb_a = Address::generate(&env);
    let arb_b = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"arb_id");

    let id_a = client.derive_escrow_id(&token, &100i128, &owner, &salt, &0u64, &Some(arb_a));
    let id_b = client.derive_escrow_id(&token, &100i128, &owner, &salt, &0u64, &Some(arb_b));
    assert_ne!(id_a, id_b);
}

// ============================================================================
// Invariant 3: Domain separation — escrow_id ≠ commitment for same inputs.
// ============================================================================

#[test]
fn test_escrow_id_domain_separated_from_commitment() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner = Address::generate(&env);
    let amount = 1_000i128;
    let salt = Bytes::from_slice(&env, b"separate");

    let commitment = client.create_amount_commitment(&owner, &amount, &salt);
    let id = client.derive_escrow_id(&token, &amount, &owner, &salt, &0u64, &None);

    // Different hashes over overlapping inputs MUST differ thanks to the
    // domain tag and additional fields.
    assert_ne!(commitment, id);
}

// ============================================================================
// Invariant 4: Unambiguous boundaries — length-prefixing prevents ambiguity.
// ============================================================================

#[test]
fn test_escrow_id_length_prefix_distinguishes_salt_boundary() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner = Address::generate(&env);

    // Without length prefixes, the serialization of two very similar
    // salts that differ only in length would be easier to confuse. The
    // length prefix guarantees distinct serializations and hence ids.
    let id_short = client.derive_escrow_id(
        &token,
        &100i128,
        &owner,
        &Bytes::from_slice(&env, b"aa"),
        &0u64,
        &None,
    );
    let id_long = client.derive_escrow_id(
        &token,
        &100i128,
        &owner,
        &Bytes::from_slice(&env, b"aaa"),
        &0u64,
        &None,
    );
    assert_ne!(id_short, id_long);
}

#[test]
fn test_escrow_id_empty_salt_still_derives() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner = Address::generate(&env);

    let id = client.derive_escrow_id(&token, &100i128, &owner, &Bytes::new(&env), &0u64, &None);
    assert_eq!(id.len(), 32);
}

// ============================================================================
// Input validation.
// ============================================================================

#[test]
fn test_escrow_id_rejects_negative_amount() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"neg");

    let result = client.try_derive_escrow_id(&token, &-1i128, &owner, &salt, &0u64, &None);
    assert_eq!(result, Err(Ok(crate::errors::QuickexError::InvalidAmount)));
}

#[test]
fn test_escrow_id_rejects_oversized_salt() {
    let (env, client) = setup();
    let token = Address::generate(&env);
    let owner = Address::generate(&env);

    let mut large_salt = Bytes::new(&env);
    for _ in 0..1025 {
        large_salt.push_back(0xAA);
    }

    let result = client.try_derive_escrow_id(&token, &100i128, &owner, &large_salt, &0u64, &None);
    assert_eq!(result, Err(Ok(crate::errors::QuickexError::InvalidSalt)));
}

// ============================================================================
// Acceptance criteria: duplicate deposits return existing escrow
// deterministically.
// ============================================================================

#[test]
fn test_deposit_idempotent_on_identical_params() {
    let (env, client) = setup();
    let (token, mint_client, token_client) = register_token(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"idem");
    let amount = 1_000i128;

    // Fund the owner so the first deposit succeeds. The second deposit
    // must NOT transfer again — idempotent behavior returns the existing
    // commitment without a second transfer.
    mint_client.mint(&owner, &amount);

    let commitment1 = client.deposit(&token, &amount, &owner, &salt, &0u64, &None);

    // After first deposit, owner's balance is 0 (transferred to contract).
    assert_eq!(token_client.balance(&owner), 0);

    // Re-submit the same exact request: should dedupe and return the
    // same commitment, without pulling more funds.
    let commitment2 = client.deposit(&token, &amount, &owner, &salt, &0u64, &None);
    assert_eq!(commitment1, commitment2);
    assert_eq!(token_client.balance(&owner), 0);

    // The escrow-id → commitment mapping should resolve to the stored
    // commitment, proving the derivation is observable on-chain.
    let escrow_id = client.derive_escrow_id(&token, &amount, &owner, &salt, &0u64, &None);
    let mapped = client.get_escrow_id_commitment(&escrow_id);
    assert_eq!(mapped, Some(commitment1));
}

#[test]
fn test_deposit_different_params_yield_different_ids() {
    let (env, client) = setup();
    let (token, mint_client, _) = register_token(&env);
    let owner = Address::generate(&env);
    let amount = 500i128;

    mint_client.mint(&owner, &(amount * 2));

    let c1 = client.deposit(
        &token,
        &amount,
        &owner,
        &Bytes::from_slice(&env, b"s1"),
        &0u64,
        &None,
    );
    let c2 = client.deposit(
        &token,
        &amount,
        &owner,
        &Bytes::from_slice(&env, b"s2"),
        &0u64,
        &None,
    );
    assert_ne!(c1, c2);

    let id1 = client.derive_escrow_id(
        &token,
        &amount,
        &owner,
        &Bytes::from_slice(&env, b"s1"),
        &0u64,
        &None,
    );
    let id2 = client.derive_escrow_id(
        &token,
        &amount,
        &owner,
        &Bytes::from_slice(&env, b"s2"),
        &0u64,
        &None,
    );
    assert_ne!(id1, id2);
}
