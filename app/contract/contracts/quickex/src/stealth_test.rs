//! Tests for the stealth address PoC (Issue #157 – Privacy v2).

use crate::{errors::QuickexError, stealth, EscrowStatus, QuickexContract, QuickexContractClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, BytesN, Env,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup<'a>() -> (Env, QuickexContractClient<'a>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    (env, client)
}

fn create_test_token(env: &Env) -> Address {
    env.register_stellar_asset_contract_v2(Address::generate(env))
        .address()
}

/// Simulate the off-chain DH key derivation so tests can compute the correct
/// stealth address without needing a real EC library.
fn compute_stealth_address(
    env: &Env,
    eph_pub: &BytesN<32>,
    spend_pub: &BytesN<32>,
) -> BytesN<32> {
    let shared = stealth::derive_shared_secret(env, eph_pub, spend_pub);
    stealth::derive_stealth_address(env, spend_pub, &shared)
}

/// Mint `amount` tokens to `recipient` via the test token admin.
fn mint(env: &Env, token: &Address, recipient: &Address, amount: i128) {
    let token_client = token::StellarAssetClient::new(env, token);
    token_client.mint(recipient, &amount);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy path: sender registers ephemeral key, recipient withdraws.
#[test]
fn test_stealth_full_flow() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let amount: i128 = 1_000;

    // Simulate key material (32-byte blobs).
    let eph_pub: BytesN<32> = BytesN::from_array(&env, &[1u8; 32]);
    let spend_pub: BytesN<32> = BytesN::from_array(&env, &[2u8; 32]);
    let stealth_address = compute_stealth_address(&env, &eph_pub, &spend_pub);

    // Fund sender.
    mint(&env, &token, &sender, amount);

    // Sender registers ephemeral key and locks funds.
    let returned_stealth = client
        .register_ephemeral_key(
            &sender,
            &token,
            &amount,
            &eph_pub,
            &spend_pub,
            &stealth_address,
            &0,
        );

    assert_eq!(returned_stealth, stealth_address);

    // Status should be Pending.
    assert_eq!(
        client.get_stealth_status(&stealth_address),
        Some(EscrowStatus::Pending)
    );

    // Recipient withdraws.
    let ok = client
        .stealth_withdraw(&recipient, &eph_pub, &spend_pub, &stealth_address);

    assert!(ok);

    // Status should now be Spent.
    assert_eq!(
        client.get_stealth_status(&stealth_address),
        Some(EscrowStatus::Spent)
    );

    // Recipient should have received the tokens.
    let token_client = token::Client::new(&env, &token);
    assert_eq!(token_client.balance(&recipient), amount);
}

/// Registering with a wrong stealth address (mismatched DH) must fail.
#[test]
fn test_register_wrong_stealth_address_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let sender = Address::generate(&env);
    let amount: i128 = 500;

    let eph_pub: BytesN<32> = BytesN::from_array(&env, &[3u8; 32]);
    let spend_pub: BytesN<32> = BytesN::from_array(&env, &[4u8; 32]);
    // Deliberately wrong stealth address.
    let wrong_stealth: BytesN<32> = BytesN::from_array(&env, &[0u8; 32]);

    mint(&env, &token, &sender, amount);

    let err = client
        .try_register_ephemeral_key(
            &sender,
            &token,
            &amount,
            &eph_pub,
            &spend_pub,
            &wrong_stealth,
            &0,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::StealthAddressMismatch.into());
}

/// Registering the same stealth address twice must fail.
#[test]
fn test_register_duplicate_stealth_address_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let sender = Address::generate(&env);
    let amount: i128 = 200;

    let eph_pub: BytesN<32> = BytesN::from_array(&env, &[5u8; 32]);
    let spend_pub: BytesN<32> = BytesN::from_array(&env, &[6u8; 32]);
    let stealth_address = compute_stealth_address(&env, &eph_pub, &spend_pub);

    mint(&env, &token, &sender, amount * 2);

    // First registration succeeds.
    client
        .register_ephemeral_key(
            &sender,
            &token,
            &amount,
            &eph_pub,
            &spend_pub,
            &stealth_address,
            &0,
        );

    // Second registration with same stealth address must fail.
    let err = client
        .try_register_ephemeral_key(
            &sender,
            &token,
            &amount,
            &eph_pub,
            &spend_pub,
            &stealth_address,
            &0,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::StealthAddressAlreadyUsed.into());
}

/// Withdrawing with wrong spend_pub must fail.
#[test]
fn test_stealth_withdraw_wrong_spend_pub_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let amount: i128 = 300;

    let eph_pub: BytesN<32> = BytesN::from_array(&env, &[7u8; 32]);
    let spend_pub: BytesN<32> = BytesN::from_array(&env, &[8u8; 32]);
    let stealth_address = compute_stealth_address(&env, &eph_pub, &spend_pub);

    mint(&env, &token, &sender, amount);

    client
        .register_ephemeral_key(
            &sender,
            &token,
            &amount,
            &eph_pub,
            &spend_pub,
            &stealth_address,
            &0,
        );

    // Use a different spend_pub at withdrawal.
    let wrong_spend_pub: BytesN<32> = BytesN::from_array(&env, &[99u8; 32]);

    let err = client
        .try_stealth_withdraw(&recipient, &eph_pub, &wrong_spend_pub, &stealth_address)
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::StealthAddressMismatch.into());
}

/// Double withdrawal must fail with AlreadySpent.
#[test]
fn test_stealth_double_withdraw_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let amount: i128 = 400;

    let eph_pub: BytesN<32> = BytesN::from_array(&env, &[9u8; 32]);
    let spend_pub: BytesN<32> = BytesN::from_array(&env, &[10u8; 32]);
    let stealth_address = compute_stealth_address(&env, &eph_pub, &spend_pub);

    mint(&env, &token, &sender, amount);

    client
        .register_ephemeral_key(
            &sender,
            &token,
            &amount,
            &eph_pub,
            &spend_pub,
            &stealth_address,
            &0,
        );

    // First withdrawal succeeds.
    client
        .stealth_withdraw(&recipient, &eph_pub, &spend_pub, &stealth_address);

    // Second withdrawal must fail.
    let err = client
        .try_stealth_withdraw(&recipient, &eph_pub, &spend_pub, &stealth_address)
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::AlreadySpent.into());
}

/// Withdrawal after expiry must fail with EscrowExpired.
#[test]
fn test_stealth_withdraw_after_expiry_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let amount: i128 = 600;

    let eph_pub: BytesN<32> = BytesN::from_array(&env, &[11u8; 32]);
    let spend_pub: BytesN<32> = BytesN::from_array(&env, &[12u8; 32]);
    let stealth_address = compute_stealth_address(&env, &eph_pub, &spend_pub);

    mint(&env, &token, &sender, amount);

    // Register with a 100-second timeout.
    client
        .register_ephemeral_key(
            &sender,
            &token,
            &amount,
            &eph_pub,
            &spend_pub,
            &stealth_address,
            &100,
        );

    // Advance ledger past expiry.
    env.ledger().with_mut(|l| l.timestamp += 200);

    let err = client
        .try_stealth_withdraw(&recipient, &eph_pub, &spend_pub, &stealth_address)
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::EscrowExpired.into());
}

/// Registering with zero amount must fail.
#[test]
fn test_stealth_register_zero_amount_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let sender = Address::generate(&env);

    let eph_pub: BytesN<32> = BytesN::from_array(&env, &[13u8; 32]);
    let spend_pub: BytesN<32> = BytesN::from_array(&env, &[14u8; 32]);
    let stealth_address = compute_stealth_address(&env, &eph_pub, &spend_pub);

    let err = client
        .try_register_ephemeral_key(
            &sender,
            &token,
            &0,
            &eph_pub,
            &spend_pub,
            &stealth_address,
            &0,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::InvalidAmount.into());
}

/// Querying a non-existent stealth address returns None.
#[test]
fn test_get_stealth_status_not_found() {
    let (env, client) = setup();
    let unknown: BytesN<32> = BytesN::from_array(&env, &[0u8; 32]);
    assert_eq!(client.get_stealth_status(&unknown), None);
}

/// When contract is paused, register_ephemeral_key must fail.
#[test]
fn test_stealth_register_fails_when_paused() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let sender = Address::generate(&env);
    let admin = Address::generate(&env);
    let amount: i128 = 100;

    let eph_pub: BytesN<32> = BytesN::from_array(&env, &[15u8; 32]);
    let spend_pub: BytesN<32> = BytesN::from_array(&env, &[16u8; 32]);
    let stealth_address = compute_stealth_address(&env, &eph_pub, &spend_pub);

    client.initialize(&admin);
    client.set_paused(&admin, &true);

    mint(&env, &token, &sender, amount);

    let err = client
        .try_register_ephemeral_key(
            &sender,
            &token,
            &amount,
            &eph_pub,
            &spend_pub,
            &stealth_address,
            &0,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::ContractPaused.into());
}
