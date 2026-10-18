//! Regression tests for Issue #1163:
//! "Escrow Cleanup Leaves Stale Escrow-ID Mappings, Causing Silent No-Op Re-Deposits".
//!
//! Before the fix, [`crate::storage::remove_escrow`] deleted the escrow's
//! compact / dispute / legacy keys but left the
//! [`crate::storage::DataKey::EscrowIdMap`] entry in place. A later
//! `deposit` / `deposit_multi_sig` call with the *same* creation payload
//! hit the stale mapping, returned the old commitment, and skipped the
//! token transfer — so no funds moved and no new escrow was written, while
//! [`QuickexContract::get_commitment_state`] on the returned commitment
//! returned `None`.
//!
//! These tests assert:
//! 1. After deposit → withdraw → cleanup, re-depositing the same payload
//!    performs a real token transfer and creates a new escrow.
//! 2. The old silent-no-op behavior no longer occurs.
//! 3. The single-sig and multi-sig deposit paths are both covered.
//! 4. The existing idempotency guarantee still holds for the non-cleanup
//!    case (re-submitting before cleanup dedupes without a second transfer).

use crate::{QuickexContract, QuickexContractClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token::{StellarAssetClient, TokenClient},
    Address, Bytes, Env, Vec,
};

extern crate std;

fn setup<'a>() -> (Env, QuickexContractClient<'a>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    (env, client)
}

/// Register a SAC test token and return (token_address, mint_client, token_client).
fn register_token<'a>(env: &'a Env) -> (Address, StellarAssetClient<'a>, TokenClient<'a>) {
    let admin = Address::generate(env);
    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = sac.address();
    let mint_client = StellarAssetClient::new(env, &token_address);
    let token_client = TokenClient::new(env, &token_address);
    (token_address, mint_client, token_client)
}

// ============================================================================
// Single-sig: deposit → withdraw → cleanup → re-deposit must move funds.
// ============================================================================

#[test]
fn test_redeposit_after_cleanup_transfers_funds_single_sig() {
    let (env, client) = setup();
    let (token, mint_client, token_client) = register_token(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"cleanup_redeposit");
    let amount = 1_000i128;

    // Fund the owner with enough for both the original and the re-deposit.
    mint_client.mint(&owner, &(amount * 2));

    // 1. First deposit.
    let commitment1 = client.deposit(
        &token,
        &amount,
        &owner,
        &salt,
        &0u64,
        &None,
        &0u64,
        &u64::MAX,
    );
    // Owner transferred `amount` to the contract.
    assert_eq!(token_client.balance(&owner), amount);

    // 2. Withdraw (move escrow to Spent terminal state). `to` is the owner
    //    so the same commitment proof applies; with no fee config the full
    //    amount returns to the owner.
    client.withdraw(&token, &amount, &commitment1, &owner, &salt, &1u64, &u64::MAX);
    // Balance back to the minted total (deposit returned in full).
    assert_eq!(token_client.balance(&owner), amount * 2);

    // 3. Cleanup the terminal escrow. cleanup_escrow requires an initialized
    //    admin, so set one up first.
    let admin = Address::generate(&env);
    client.initialize(&admin);
    client.cleanup_escrow(&commitment1).unwrap();

    // The escrow-id mapping must now be gone.
    let escrow_id = client.derive_escrow_id(&token, &amount, &owner, &salt, &0u64, &None);
    assert_eq!(
        client.get_escrow_id_commitment(&escrow_id),
        None,
        "EscrowIdMap must be cleared after cleanup"
    );

    // The escrow entry itself must be gone.
    assert!(
        client.get_commitment_state(&commitment1).is_none(),
        "commitment state must be None after cleanup"
    );

    // 4. Re-deposit the exact same payload. Before the fix this would return
    //    the stale commitment with no transfer. After the fix it must perform
    //    a real token transfer and create a new escrow.
    let balance_before = token_client.balance(&owner);
    let commitment2 = client.deposit(
        &token,
        &amount,
        &owner,
        &salt,
        &0u64,
        &None,
        &2u64,
        &u64::MAX,
    );

    // A real transfer occurred: owner balance dropped by `amount`.
    assert_eq!(
        token_client.balance(&owner),
        balance_before - amount,
        "re-deposit after cleanup must transfer funds"
    );

    // The new commitment is observable on-chain (escrow entry exists).
    assert!(
        client.get_commitment_state(&commitment2).is_some(),
        "a new escrow must be created after cleanup re-deposit"
    );

    // The escrow-id mapping is re-populated pointing at the new commitment.
    let escrow_id = client.derive_escrow_id(&token, &amount, &owner, &salt, &0u64, &None);
    assert_eq!(
        client.get_escrow_id_commitment(&escrow_id),
        Some(commitment2.clone()),
        "EscrowIdMap must point at the new commitment after re-deposit"
    );
}

// ============================================================================
// Single-sig: regression — the old silent no-op no longer occurs.
// ============================================================================

#[test]
fn test_regression_stale_mapping_no_longer_causes_silent_noop_single_sig() {
    let (env, client) = setup();
    let (token, mint_client, token_client) = register_token(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"stale_noop");
    let amount = 500i128;

    mint_client.mint(&owner, &(amount * 2));

    // Deposit, withdraw, cleanup.
    let commitment1 = client.deposit(
        &token,
        &amount,
        &owner,
        &salt,
        &0u64,
        &None,
        &0u64,
        &u64::MAX,
    );
    client.withdraw(&token, &amount, &commitment1, &owner, &salt, &1u64, &u64::MAX);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    client.cleanup_escrow(&commitment1).unwrap();

    // Re-deposit with identical params.
    let balance_before_redeposit = token_client.balance(&owner);
    let commitment2 = client.deposit(
        &token,
        &amount,
        &owner,
        &salt,
        &0u64,
        &None,
        &2u64,
        &u64::MAX,
    );

    // Before the fix: commitment2 == commitment1 AND owner balance unchanged
    // (no transfer). After the fix: a transfer occurs. The defining symptom
    // of the bug is that no funds move on re-deposit, so assert the owner's
    // balance actually decreased (a real transfer happened).
    assert_ne!(
        token_client.balance(&owner),
        balance_before_redeposit,
        "stale-mapping silent no-op must not occur: funds must move on re-deposit"
    );
    assert_eq!(
        token_client.balance(&owner),
        balance_before_redeposit - amount,
        "exactly `amount` must be transferred on re-deposit after cleanup"
    );

    // And the new escrow must be present on-chain.
    assert!(
        client.get_commitment_state(&commitment2).is_some(),
        "new escrow must exist after re-deposit"
    );
}

// ============================================================================
// Multi-sig: deposit → finalize_expired_escrow (Refunded) → cleanup → re-deposit.
// ============================================================================

#[test]
fn test_redeposit_after_cleanup_transfers_funds_multi_sig() {
    let (env, client) = setup();
    let (token, mint_client, token_client) = register_token(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"multi_cleanup");
    let amount = 800i128;
    let timeout_secs = 3600u64;

    let arbiter_a = Address::generate(&env);
    let arbiter_b = Address::generate(&env);
    let mut arbiters = Vec::new(&env);
    arbiters.push_back(arbiter_a);
    arbiters.push_back(arbiter_b);
    let threshold = 1u32;

    mint_client.mint(&owner, &(amount * 2));

    // 1. First multi-sig deposit.
    let commitment1 = client.deposit_multi_sig(
        &token,
        &amount,
        &owner,
        &salt,
        &timeout_secs,
        &arbiters,
        &threshold,
        &0u64,
        &u64::MAX,
    );
    assert_eq!(token_client.balance(&owner), amount);

    // 2. Expire the escrow and finalize a refund (terminal Refunded state).
    let now = env.ledger().timestamp();
    env.ledger().set_timestamp(now + timeout_secs + 1);
    client.finalize_expired_escrow(&commitment1).unwrap();
    // Funds returned to owner (no fee configured): balance back to the minted total.
    assert_eq!(token_client.balance(&owner), amount * 2);

    // 3. Cleanup the refunded escrow.
    let admin = Address::generate(&env);
    client.initialize(&admin);
    client.cleanup_escrow(&commitment1).unwrap();

    // The multi-sig escrow-id mapping must be cleared.
    let escrow_id = client.derive_escrow_id_multi_sig(
        &token,
        &amount,
        &owner,
        &salt,
        &timeout_secs,
        &arbiters,
        &threshold,
    );
    assert_eq!(
        client.get_escrow_id_commitment(&escrow_id),
        None,
        "multi-sig EscrowIdMap must be cleared after cleanup"
    );

    // 4. Re-deposit identical multi-sig payload — must transfer funds.
    let balance_before = token_client.balance(&owner);
    let commitment2 = client.deposit_multi_sig(
        &token,
        &amount,
        &owner,
        &salt,
        &timeout_secs,
        &arbiters,
        &threshold,
        &1u64,
        &u64::MAX,
    );

    assert_eq!(
        token_client.balance(&owner),
        balance_before - amount,
        "multi-sig re-deposit after cleanup must transfer funds"
    );

    assert!(
        client.get_commitment_state(&commitment2).is_some(),
        "a new multi-sig escrow must be created after cleanup re-deposit"
    );

    let escrow_id = client.derive_escrow_id_multi_sig(
        &token,
        &amount,
        &owner,
        &salt,
        &timeout_secs,
        &arbiters,
        &threshold,
    );
    assert_eq!(
        client.get_escrow_id_commitment(&escrow_id),
        Some(commitment2.clone()),
        "multi-sig EscrowIdMap must point at the new commitment after re-deposit"
    );
}

// ============================================================================
// Idempotency still holds for the non-cleanup case (acceptance criterion 4).
// ============================================================================

#[test]
fn test_idempotent_redeposit_still_dedupes_without_cleanup() {
    let (env, client) = setup();
    let (token, mint_client, token_client) = register_token(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"idem_no_cleanup");
    let amount = 1_000i128;

    mint_client.mint(&owner, &amount);

    let commitment1 = client.deposit(
        &token,
        &amount,
        &owner,
        &salt,
        &0u64,
        &None,
        &0u64,
        &u64::MAX,
    );
    assert_eq!(token_client.balance(&owner), 0);

    // Re-submit identical params WITHOUT a cleanup in between: must dedupe
    // and return the same commitment without a second transfer.
    let commitment2 = client.deposit(
        &token,
        &amount,
        &owner,
        &salt,
        &0u64,
        &None,
        &1u64,
        &u64::MAX,
    );
    assert_eq!(commitment1, commitment2);
    assert_eq!(
        token_client.balance(&owner),
        0,
        "idempotent re-deposit without cleanup must not transfer funds"
    );

    let escrow_id = client.derive_escrow_id(&token, &amount, &owner, &salt, &0u64, &None);
    assert_eq!(client.get_escrow_id_commitment(&escrow_id), Some(commitment1));
}
