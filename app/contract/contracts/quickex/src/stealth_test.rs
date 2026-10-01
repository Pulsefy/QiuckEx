//! Tests for the stealth address PoC (Issue #157 – Privacy v2).

use crate::{
    errors::QuickexError, stealth, types::StealthDepositParams, EscrowStatus, QuickexContract,
    QuickexContractClient,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, BytesN, Env,
};

/// Default nonce and valid_until values for test helper calls.
/// These are passed to functions that now require nonce verification.
/// Each test uses a unique nonce to avoid collisions.
#[allow(dead_code)]
const TEST_NONCE_BASE: u64 = 9000;
const TEST_VALID_UNTIL: u64 = 2_000_000;

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

/// Apply the contract's documented hash derivation in tests.
fn compute_stealth_address(env: &Env, eph_pub: &BytesN<32>, spend_pub: &BytesN<32>) -> BytesN<32> {
    let shared = stealth::derive_shared_secret(env, eph_pub, spend_pub);
    stealth::derive_stealth_address(env, spend_pub, &shared)
}

fn assert_derivation_vector(
    env: &Env,
    eph_pub: &[u8; 32],
    spend_pub: &[u8; 32],
    expected_shared: &[u8; 32],
    expected_stealth: &[u8; 32],
) -> BytesN<32> {
    let eph_pub = BytesN::from_array(env, eph_pub);
    let spend_pub = BytesN::from_array(env, spend_pub);
    let shared = stealth::derive_shared_secret(env, &eph_pub, &spend_pub);
    assert_eq!(shared, BytesN::from_array(env, expected_shared));

    let stealth_id = stealth::derive_stealth_address(env, &spend_pub, &shared);
    assert_eq!(stealth_id, BytesN::from_array(env, expected_stealth));
    stealth_id
}

/// Mint `amount` tokens to `recipient`.
fn mint(env: &Env, token: &Address, recipient: &Address, amount: i128) {
    token::StellarAssetClient::new(env, token).mint(recipient, &amount);
}

/// Build a `StealthDepositParams` with the given fields.
#[allow(clippy::too_many_arguments)]
fn make_params(
    sender: Address,
    token: Address,
    amount_due: i128,
    amount_paid: i128,
    eph_pub: BytesN<32>,
    spend_pub: BytesN<32>,
    stealth_address: BytesN<32>,
    timeout_secs: u64,
) -> StealthDepositParams {
    StealthDepositParams {
        sender,
        token,
        amount_due,
        amount_paid,
        eph_pub,
        spend_pub,
        stealth_address,
        timeout_secs,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Independent SHA-256 vectors covering byte order and boundary byte values.
#[test]
fn test_stealth_derivation_fixed_vectors() {
    let env = Env::default();
    let ascending: [u8; 32] = core::array::from_fn(|i| i as u8);
    let descending_half: [u8; 32] = core::array::from_fn(|i| (i + 32) as u8);
    let zeros = [0u8; 32];
    let max_bytes = [u8::MAX; 32];

    assert_derivation_vector(
        &env,
        &ascending,
        &descending_half,
        &[
            0xfd, 0xea, 0xb9, 0xac, 0xf3, 0x71, 0x03, 0x62, 0xbd, 0x26, 0x58, 0xcd, 0xc9, 0xa2,
            0x9e, 0x8f, 0x9c, 0x75, 0x7f, 0xcf, 0x98, 0x11, 0x60, 0x3a, 0x8c, 0x44, 0x7c, 0xd1,
            0xd9, 0x15, 0x11, 0x08,
        ],
        &[
            0xe8, 0xbc, 0x2d, 0x63, 0x24, 0xc9, 0x97, 0xc9, 0xd7, 0x3b, 0xf2, 0x8c, 0x7d, 0x72,
            0xe5, 0xe9, 0x0d, 0x03, 0x00, 0xae, 0xdf, 0x68, 0x52, 0xdc, 0x07, 0xd8, 0x5e, 0x76,
            0xf6, 0xea, 0x68, 0xd4,
        ],
    );

    assert_derivation_vector(
        &env,
        &zeros,
        &zeros,
        &[
            0xf5, 0xa5, 0xfd, 0x42, 0xd1, 0x6a, 0x20, 0x30, 0x27, 0x98, 0xef, 0x6e, 0xd3, 0x09,
            0x97, 0x9b, 0x43, 0x00, 0x3d, 0x23, 0x20, 0xd9, 0xf0, 0xe8, 0xea, 0x98, 0x31, 0xa9,
            0x27, 0x59, 0xfb, 0x4b,
        ],
        &[
            0xb6, 0x2c, 0x0b, 0xf3, 0x6d, 0x7f, 0xee, 0x9a, 0x6e, 0xd4, 0x9f, 0x75, 0x29, 0xe9,
            0xfb, 0xf6, 0xeb, 0xc9, 0x32, 0x68, 0xf4, 0x38, 0x32, 0xb4, 0x03, 0x3e, 0xef, 0x0b,
            0xa3, 0x35, 0xba, 0x65,
        ],
    );

    assert_derivation_vector(
        &env,
        &max_bytes,
        &max_bytes,
        &[
            0x86, 0x67, 0xe7, 0x18, 0x29, 0x4e, 0x9e, 0x0d, 0xf1, 0xd3, 0x06, 0x00, 0xba, 0x3e,
            0xeb, 0x20, 0x1f, 0x76, 0x4a, 0xad, 0x2d, 0xad, 0x72, 0x74, 0x86, 0x43, 0xe4, 0xa2,
            0x85, 0xe1, 0xd1, 0xf7,
        ],
        &[
            0x17, 0x02, 0x36, 0x84, 0xa3, 0xdf, 0x36, 0xc9, 0x18, 0x95, 0x39, 0x47, 0xec, 0x42,
            0xfc, 0xaa, 0x4d, 0x35, 0x05, 0x0f, 0xb4, 0x4c, 0x29, 0x59, 0x7f, 0xb0, 0x92, 0x01,
            0x26, 0x56, 0x5b, 0x37,
        ],
    );

    // Reversing the two distinct 32-byte inputs changes the result.
    let forward = stealth::derive_shared_secret(
        &env,
        &BytesN::from_array(&env, &ascending),
        &BytesN::from_array(&env, &descending_half),
    );
    assert_derivation_vector(
        &env,
        &descending_half,
        &ascending,
        &[
            0x84, 0xe4, 0xbd, 0x6c, 0xa2, 0xaf, 0x96, 0x41, 0x2f, 0xdc, 0x62, 0xfe, 0x44, 0xd4,
            0xe9, 0x70, 0x9c, 0xdc, 0x31, 0x93, 0x30, 0x81, 0xa6, 0x24, 0x86, 0xa4, 0x8a, 0x15,
            0x4b, 0x58, 0x2d, 0x53,
        ],
        &[
            0xf7, 0xa9, 0xbd, 0xe9, 0x0e, 0x77, 0x42, 0x40, 0x70, 0x62, 0x09, 0x15, 0xc3, 0x5e,
            0x21, 0xc9, 0x05, 0x42, 0x8a, 0x22, 0xcf, 0xb0, 0xc5, 0x9d, 0xb8, 0x4d, 0x57, 0x17,
            0x76, 0xb4, 0xb4, 0x7d,
        ],
    );
    let reversed = stealth::derive_shared_secret(
        &env,
        &BytesN::from_array(&env, &descending_half),
        &BytesN::from_array(&env, &ascending),
    );
    assert_ne!(forward, reversed);
}

/// Distinct ephemeral inputs produce distinct IDs for the same spend-key bytes.
///
/// This asserts output variation only; it is not a cryptographic unlinkability
/// guarantee because the inputs are public and the construction is not ECDH.
#[test]
fn test_same_recipient_distinct_ephemeral_inputs_produce_distinct_ids() {
    let env = Env::default();
    let spend_pub = [2u8; 32];
    let first = assert_derivation_vector(
        &env,
        &[1u8; 32],
        &spend_pub,
        &[
            0xf8, 0x18, 0xaf, 0xd3, 0x7a, 0x6d, 0xc3, 0xbc, 0x92, 0xfb, 0x44, 0x73, 0x10, 0x11,
            0x27, 0x70, 0x06, 0xdb, 0x4e, 0xfa, 0x6e, 0x90, 0x23, 0xcd, 0x74, 0x68, 0xc0, 0x23,
            0x35, 0xd2, 0x2a, 0x4d,
        ],
        &[
            0xbf, 0xa0, 0xac, 0xaa, 0x00, 0x93, 0x22, 0x7a, 0x3d, 0xb8, 0x12, 0x9d, 0xae, 0x0c,
            0x29, 0xd3, 0x17, 0x0e, 0x71, 0xda, 0x62, 0xfb, 0x33, 0xfb, 0x35, 0x9a, 0x86, 0x8c,
            0xb9, 0xd6, 0x2d, 0xca,
        ],
    );
    let second = assert_derivation_vector(
        &env,
        &[3u8; 32],
        &spend_pub,
        &[
            0xdb, 0xcd, 0x00, 0x35, 0x44, 0x3a, 0x74, 0xf5, 0x49, 0x46, 0x9e, 0x72, 0x0a, 0x48,
            0x33, 0x82, 0x83, 0x4c, 0xd9, 0xda, 0x9b, 0x96, 0x0f, 0x8b, 0x7a, 0xa7, 0xcf, 0xdf,
            0xf9, 0x02, 0xfd, 0xfb,
        ],
        &[
            0xe6, 0x67, 0x50, 0x4b, 0x73, 0xf5, 0x70, 0x81, 0x48, 0xd4, 0x32, 0xe6, 0xd5, 0xc0,
            0x40, 0x35, 0x57, 0x72, 0xab, 0x5a, 0x40, 0xbb, 0xdc, 0xac, 0x78, 0x2f, 0x33, 0x2d,
            0x2c, 0x1a, 0x84, 0xc1,
        ],
    );
    assert_ne!(first, second);
}

/// Happy path: sender registers ephemeral key, recipient withdraws.
#[test]
fn test_stealth_full_flow() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let amount: i128 = 1_000;

    let eph_pub: BytesN<32> = BytesN::from_array(&env, &[1u8; 32]);
    let spend_pub: BytesN<32> = BytesN::from_array(&env, &[2u8; 32]);
    let stealth_address = compute_stealth_address(&env, &eph_pub, &spend_pub);

    mint(&env, &token, &sender, amount);

    let returned_stealth = client.register_ephemeral_key(
        &make_params(
            sender,
            token.clone(),
            amount,
            amount,
            eph_pub.clone(),
            spend_pub.clone(),
            stealth_address.clone(),
            0,
        ),
        &1000,
        &2000000,
    );

    assert_eq!(returned_stealth, stealth_address);
    assert_eq!(
        client.get_stealth_status(&stealth_address),
        Some(EscrowStatus::Pending)
    );

    let ok = client.stealth_withdraw(
        &recipient,
        &eph_pub,
        &spend_pub,
        &stealth_address,
        &1000,
        &TEST_VALID_UNTIL,
    );
    assert!(ok);

    assert_eq!(
        client.get_stealth_status(&stealth_address),
        Some(EscrowStatus::Spent)
    );

    let token_client = token::Client::new(&env, &token);
    assert_eq!(token_client.balance(&recipient), amount);
}

/// Registering with a wrong stealth address must fail.
#[test]
fn test_register_wrong_stealth_address_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let sender = Address::generate(&env);
    let amount: i128 = 500;

    let eph_pub: BytesN<32> = BytesN::from_array(&env, &[3u8; 32]);
    let spend_pub: BytesN<32> = BytesN::from_array(&env, &[4u8; 32]);
    let wrong_stealth: BytesN<32> = BytesN::from_array(&env, &[0u8; 32]);

    mint(&env, &token, &sender, amount);

    let err = client
        .try_register_ephemeral_key(
            &make_params(
                sender,
                token,
                amount,
                amount,
                eph_pub,
                spend_pub,
                wrong_stealth,
                0,
            ),
            &1001,
            &2000000,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::StealthAddressMismatch);
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

    client.register_ephemeral_key(
        &make_params(
            sender.clone(),
            token.clone(),
            amount,
            amount,
            eph_pub.clone(),
            spend_pub.clone(),
            stealth_address.clone(),
            0,
        ),
        &1001,
        &TEST_VALID_UNTIL,
    );

    let err = client
        .try_register_ephemeral_key(
            &make_params(
                sender,
                token,
                amount,
                amount,
                eph_pub,
                spend_pub,
                stealth_address,
                0,
            ),
            &1002,
            &TEST_VALID_UNTIL,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::StealthAddressAlreadyUsed);
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

    client.register_ephemeral_key(
        &make_params(
            sender,
            token,
            amount,
            amount,
            eph_pub.clone(),
            spend_pub,
            stealth_address.clone(),
            0,
        ),
        &1001,
        &TEST_VALID_UNTIL,
    );

    let wrong_spend_pub: BytesN<32> = BytesN::from_array(&env, &[99u8; 32]);

    let err = client
        .try_stealth_withdraw(
            &recipient,
            &eph_pub,
            &wrong_spend_pub,
            &stealth_address,
            &1002,
            &TEST_VALID_UNTIL,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::StealthAddressMismatch);
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

    client.register_ephemeral_key(
        &make_params(
            sender,
            token,
            amount,
            amount,
            eph_pub.clone(),
            spend_pub.clone(),
            stealth_address.clone(),
            0,
        ),
        &1001,
        &TEST_VALID_UNTIL,
    );

    client.stealth_withdraw(
        &recipient,
        &eph_pub,
        &spend_pub,
        &stealth_address,
        &1002,
        &TEST_VALID_UNTIL,
    );

    let err = client
        .try_stealth_withdraw(
            &recipient,
            &eph_pub,
            &spend_pub,
            &stealth_address,
            &1003,
            &TEST_VALID_UNTIL,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::AlreadySpent);
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

    client.register_ephemeral_key(
        &make_params(
            sender,
            token,
            amount,
            amount,
            eph_pub.clone(),
            spend_pub.clone(),
            stealth_address.clone(),
            100,
        ),
        &1001,
        &2000000,
    );

    env.ledger().with_mut(|l| l.timestamp += 200);

    let err = client
        .try_stealth_withdraw(
            &recipient,
            &eph_pub,
            &spend_pub,
            &stealth_address,
            &1002,
            &2000001,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::EscrowExpired);
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
            &make_params(sender, token, 0, 0, eph_pub, spend_pub, stealth_address, 0),
            &1001,
            &2000000,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::InvalidAmount);
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
    client.set_paused(&admin, &true, &1u32);

    mint(&env, &token, &sender, amount);

    let err = client
        .try_register_ephemeral_key(
            &make_params(
                sender,
                token,
                amount,
                amount,
                eph_pub,
                spend_pub,
                stealth_address,
                0,
            ),
            &1001,
            &2000000,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, QuickexError::ContractPaused);
}
