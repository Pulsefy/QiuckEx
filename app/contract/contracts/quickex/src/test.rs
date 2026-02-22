//! QuickEx contract integration tests.
//!
//! ## Upgrade / regression suite
//!
//! A minimal set of **golden path** tests is maintained for upgrade safety: after contract or
//! SDK upgrades, re-run these to ensure existing escrows and commitments still behave correctly.
//!
//! **Golden path tests (regression suite):**
//! - **Escrows & commitments:** `test_deposit`, `test_successful_withdrawal`, `test_commitment_cycle`
//! - **Privacy toggle:** `test_set_privacy_toggle_cycle_succeeds`, `test_set_and_get_privacy`
//! - **Refunds:** `test_refund_successful`
//! - **Single full-flow smoke test:** `regression_golden_path_full_flow`
//!
//! How to re-run only the regression suite:
//!
//! ```sh
//! cargo test regression_
//! cargo test test_deposit test_successful_withdrawal test_refund_successful test_set_privacy_toggle_cycle_succeeds test_set_and_get_privacy test_commitment_cycle
//! ```
//!
//! Snapshots for these tests live in `test_snapshots/`. See `REGRESSION_TESTS.md` in this
//! contract directory for how to extend the suite when adding new features.

use crate::{
    errors::QuickexError, storage::put_escrow, EscrowEntry, EscrowStatus, QuickexContract,
    QuickexContractClient,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token,
    xdr::ToXdr,
    Address, Bytes, BytesN, ConversionError, Env, InvokeError,
};

fn setup<'a>() -> (Env, QuickexContractClient<'a>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    (env, client)
}

fn setup_escrow(
    env: &Env,
    contract_id: &Address,
    token: &Address,
    amount: i128,
    commitment: BytesN<32>,
    expires_at: u64,
) {
    let depositor = Address::generate(env);

    let entry = EscrowEntry {
        token: token.clone(),
        amount,
        owner: depositor,
        status: EscrowStatus::Pending,
        created_at: env.ledger().timestamp(),
        expires_at,
    };

    env.as_contract(contract_id, || {
        // Use the new storage system to put the escrow entry
        let storage_commitment: Bytes = commitment.into();
        put_escrow(env, &storage_commitment, &entry);
    });
}

// ============================================================================
// Privacy Enforcement Tests
// ============================================================================

/// Helper: create an escrow entry in storage with a known owner address.
fn setup_escrow_with_owner(
    env: &Env,
    contract_id: &Address,
    token: &Address,
    owner: &Address,
    amount: i128,
    commitment: BytesN<32>,
    expires_at: u64,
) {
    let entry = EscrowEntry {
        token: token.clone(),
        amount,
        owner: owner.clone(),
        status: EscrowStatus::Pending,
        created_at: env.ledger().timestamp(),
        expires_at,
    };
    env.as_contract(contract_id, || {
        let storage_commitment: Bytes = commitment.into();
        put_escrow(env, &storage_commitment, &entry);
    });
}

#[test]
fn test_get_escrow_details_privacy_enabled_hides_sensitive_fields() {
    // When the owner has privacy on, a stranger should see token/status/timestamps
    // but NOT amount or owner.
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let amount: i128 = 5000;
    let salt = Bytes::from_slice(&env, b"priv_hide_salt");

    let mut data = Bytes::new(&env);
    data.append(&owner.clone().to_xdr(&env));
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow_with_owner(
        &env,
        &client.address,
        &token,
        &owner,
        amount,
        commitment.clone(),
        0,
    );

    // Enable privacy for the owner
    client.set_privacy(&owner, &true);

    // Stranger queries â€” sensitive fields must be hidden
    let view = client.get_escrow_details(&commitment, &stranger).unwrap();
    assert_eq!(view.token, token);
    assert_eq!(view.status, EscrowStatus::Pending);
    assert_eq!(view.amount, None);
    assert_eq!(view.owner, None);
}

#[test]
fn test_get_escrow_details_privacy_enabled_owner_sees_full_details() {
    // When the owner has privacy on and IS the caller, they must see everything.
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let amount: i128 = 5000;
    let salt = Bytes::from_slice(&env, b"priv_owner_salt");

    let mut data = Bytes::new(&env);
    data.append(&owner.clone().to_xdr(&env));
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow_with_owner(
        &env,
        &client.address,
        &token,
        &owner,
        amount,
        commitment.clone(),
        0,
    );

    // Enable privacy for the owner
    client.set_privacy(&owner, &true);

    // Owner queries their own escrow â€” must see full details
    let view = client.get_escrow_details(&commitment, &owner).unwrap();
    assert_eq!(view.token, token);
    assert_eq!(view.status, EscrowStatus::Pending);
    assert_eq!(view.amount, Some(amount));
    assert_eq!(view.owner, Some(owner.clone()));
}

#[test]
fn test_get_escrow_details_privacy_disabled_shows_full_details() {
    // Privacy off (default) â€” any caller gets the full view.
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let amount: i128 = 2500;
    let salt = Bytes::from_slice(&env, b"priv_off_salt");

    let mut data = Bytes::new(&env);
    data.append(&owner.clone().to_xdr(&env));
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow_with_owner(
        &env,
        &client.address,
        &token,
        &owner,
        amount,
        commitment.clone(),
        0,
    );

    // Privacy is off (never set) â€” stranger still gets full data
    let view = client.get_escrow_details(&commitment, &stranger).unwrap();
    assert_eq!(view.amount, Some(amount));
    assert_eq!(view.owner, Some(owner));
    assert_eq!(view.status, EscrowStatus::Pending);
}

#[test]
fn test_set_privacy_already_set_fails() {
    // Setting privacy to a value it already has must return PrivacyAlreadySet.
    let (env, client) = setup();
    let account = Address::generate(&env);

    // Default is false; enabling once is fine.
    client.set_privacy(&account, &true);

    // Enabling again without disabling first must fail.
    let result = client.try_set_privacy(&account, &true);
    assert_contract_error(result, QuickexError::PrivacyAlreadySet);
}

/// Regression suite: privacy toggle — ensures upgrades do not break set_privacy/get_privacy.
#[test]
fn test_set_privacy_toggle_cycle_succeeds() {
    // false â†’ true â†’ false â†’ true must all succeed without error.
    let (env, client) = setup();
    let account = Address::generate(&env);

    client.set_privacy(&account, &true);
    assert!(client.get_privacy(&account));

    client.set_privacy(&account, &false);
    assert!(!client.get_privacy(&account));

    client.set_privacy(&account, &true);
    assert!(client.get_privacy(&account));
}

fn create_test_token(env: &Env) -> Address {
    env.register_stellar_asset_contract_v2(Address::generate(env))
        .address()
}

fn assert_contract_error<T>(
    result: Result<Result<T, ConversionError>, Result<QuickexError, InvokeError>>,
    expected: QuickexError,
) {
    match result {
        Err(Ok(actual)) => assert_eq!(actual, expected),
        _ => panic!("expected contract error"),
    }
}

/// Regression suite: golden path withdrawal — deposit then withdraw by proof.
#[test]
fn test_successful_withdrawal() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"test_salt_123");

    let mut data = Bytes::new(&env);

    let address_bytes: Bytes = to.clone().to_xdr(&env);

    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);

    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(&env, &client.address, &token, amount, commitment.clone(), 0);

    env.mock_all_auths();

    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&client.address, &amount);

    let _ = client.withdraw(&token, &amount, &commitment, &to, &salt);
}

#[test]
fn test_double_withdrawal_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"test_salt_456");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = to.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(&env, &client.address, &token, amount, commitment.clone(), 0);

    env.mock_all_auths();

    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&client.address, &(amount * 2));

    let first_result = client.try_withdraw(&token, &amount, &commitment, &to, &salt);
    assert!(first_result.is_ok());
    assert_eq!(first_result.unwrap(), Ok(true));
    let second_result = client.try_withdraw(&token, &amount, &commitment, &to, &salt);
    assert_contract_error(second_result, QuickexError::AlreadySpent);
}

#[test]
fn test_invalid_salt_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let amount: i128 = 1000;
    let correct_salt = Bytes::from_slice(&env, b"correct_salt");
    let wrong_salt = Bytes::from_slice(&env, b"wrong_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = to.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&correct_salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(&env, &client.address, &token, amount, commitment.clone(), 0);

    env.mock_all_auths();
    let result = client.try_withdraw(&token, &amount, &commitment, &to, &wrong_salt);
    assert_contract_error(result, QuickexError::CommitmentNotFound);
}

#[test]
fn test_invalid_amount_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let correct_amount: i128 = 1000;
    let wrong_amount: i128 = 500;
    let salt = Bytes::from_slice(&env, b"test_salt_789");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = to.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &correct_amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(
        &env,
        &client.address,
        &token,
        correct_amount,
        commitment.clone(),
        0,
    );

    env.mock_all_auths();

    let result = client.try_withdraw(&token, &wrong_amount, &commitment, &to, &salt);
    assert_contract_error(result, QuickexError::CommitmentNotFound);
}

#[test]
fn test_zero_amount_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let amount: i128 = 0;
    let salt = Bytes::from_slice(&env, b"test_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = to.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    env.mock_all_auths();

    let result = client.try_withdraw(&token, &amount, &commitment, &to, &salt);
    assert_contract_error(result, QuickexError::InvalidAmount);
}

#[test]
fn test_negative_amount_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let amount: i128 = -100;
    let salt = Bytes::from_slice(&env, b"test_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = to.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    env.mock_all_auths();

    let result = client.try_withdraw(&token, &amount, &commitment, &to, &salt);
    assert_contract_error(result, QuickexError::InvalidAmount);
}

#[test]
fn test_nonexistent_commitment_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"nonexistent");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = to.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    env.mock_all_auths();
    let result = client.try_withdraw(&token, &amount, &commitment, &to, &salt);
    assert_contract_error(result, QuickexError::CommitmentNotFound);
}

/// Regression suite: privacy get/set — default off, enable, disable.
#[test]
fn test_set_and_get_privacy() {
    let (env, client) = setup();
    let account = Address::generate(&env);

    // Default should be false
    assert!(!client.get_privacy(&account));

    // Enable privacy
    client.set_privacy(&account, &true);
    assert!(client.get_privacy(&account));

    // Disable privacy
    client.set_privacy(&account, &false);
    assert!(!client.get_privacy(&account));
}

/// Regression suite: create and verify amount commitment — core commitment flow.
#[test]
fn test_event_snapshot_privacy_toggled_schema() {
    let (env, client) = setup();
    let account = Address::generate(&env);

    client.set_privacy(&account, &true);
}

#[test]
fn test_commitment_cycle() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount = 1_000_000i128;
    let mut salt = Bytes::new(&env);
    salt.append(&Bytes::from_slice(&env, b"random_salt"));

    // Create commitment
    let commitment = client.create_amount_commitment(&owner, &amount, &salt);

    // Verify correct commitment
    let is_valid = client.verify_amount_commitment(&commitment, &owner, &amount, &salt);
    assert!(is_valid);

    // Verify incorrect amount
    let is_valid_bad_amount =
        client.verify_amount_commitment(&commitment, &owner, &2_000_000i128, &salt);
    assert!(!is_valid_bad_amount);

    // Verify incorrect salt
    let mut bad_salt = Bytes::new(&env);
    bad_salt.append(&Bytes::from_slice(&env, b"wrong_salt"));
    let is_valid_bad_salt =
        client.verify_amount_commitment(&commitment, &owner, &amount, &bad_salt);
    assert!(!is_valid_bad_salt);
}

#[test]
fn test_create_escrow() {
    let (env, client) = setup();
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    let amount = 1_000;
    let escrow_id = client.create_escrow(&from, &to, &amount);
    assert!(escrow_id > 0);
}

#[test]
fn test_health_check() {
    let (_, client) = setup();
    assert!(client.health_check());
}

#[test]
fn test_canonical_error_code_ranges() {
    // Validation failures (100-199)
    assert_eq!(QuickexError::InvalidAmount as u32, 100);
    assert_eq!(QuickexError::InvalidSalt as u32, 101);
    assert_eq!(QuickexError::InvalidPrivacyLevel as u32, 102);

    // Auth/admin failures (200-299)
    assert_eq!(QuickexError::Unauthorized as u32, 200);
    assert_eq!(QuickexError::AlreadyInitialized as u32, 201);

    // State/escrow/commitment violations (300-399)
    assert_eq!(QuickexError::ContractPaused as u32, 300);
    assert_eq!(QuickexError::PrivacyAlreadySet as u32, 301);
    assert_eq!(QuickexError::CommitmentNotFound as u32, 302);
    assert_eq!(QuickexError::CommitmentAlreadyExists as u32, 303);
    assert_eq!(QuickexError::AlreadySpent as u32, 304);
    assert_eq!(QuickexError::InvalidCommitment as u32, 305);
    assert_eq!(QuickexError::CommitmentMismatch as u32, 306);
    assert_eq!(QuickexError::EscrowExpired as u32, 307);
    assert_eq!(QuickexError::EscrowNotExpired as u32, 308);
    assert_eq!(QuickexError::InvalidOwner as u32, 309);

    // Internal/unexpected conditions (900-999)
    assert_eq!(QuickexError::InternalError as u32, 900);
}

/// Regression suite: deposit with commitment — create escrow (golden path).
#[test]
fn test_deposit() {
    let env = Env::default();
    env.mock_all_auths();

    let user = Address::generate(&env);
    let token_admin = Address::generate(&env);

    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::StellarAssetClient::new(&env, &token_id);

    token_client.mint(&user, &1000);

    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);

    let commitment = BytesN::from_array(&env, &[1; 32]);

    client.deposit_with_commitment(&user, &token_id, &500, &commitment, &0);

    assert_eq!(token_client.balance(&user), 500);
    assert_eq!(token_client.balance(&contract_id), 500);
}

#[test]
fn test_event_snapshot_escrow_deposited_schema() {
    let env = Env::default();
    env.mock_all_auths();

    let user = Address::generate(&env);
    let token_admin = Address::generate(&env);

    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::StellarAssetClient::new(&env, &token_id);
    token_client.mint(&user, &1000);

    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);

    let commitment = BytesN::from_array(&env, &[7; 32]);
    client.deposit_with_commitment(&user, &token_id, &250, &commitment, &0);
}

#[test]
fn test_initialize_admin() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin);

    // Verify admin is set
    assert_eq!(client.get_admin(), Some(admin.clone()));

    // Verify contract is not paused by default
    assert!(!client.is_paused());
}

#[test]
fn test_initialize_twice_fails() {
    let (env, client) = setup();
    let admin1 = Address::generate(&env);
    let admin2 = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin1);

    // Try to initialize again - should fail
    let result = client.try_initialize(&admin2);
    assert_contract_error(result, QuickexError::AlreadyInitialized);
}

#[test]
fn test_set_privacy_same_value_fails() {
    let (env, client) = setup();
    let account = Address::generate(&env);

    let first = client.try_set_privacy(&account, &true);
    assert_eq!(first, Ok(Ok(())));

    let second = client.try_set_privacy(&account, &true);
    assert_contract_error(second, QuickexError::PrivacyAlreadySet);
}

#[test]
fn test_deposit_with_commitment_fails_when_paused() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let token = create_test_token(&env);
    let amount: i128 = 500;
    let commitment = BytesN::from_array(&env, &[9u8; 32]);

    client.initialize(&admin);
    client.set_paused(&admin, &true);

    let result = client.try_deposit_with_commitment(&user, &token, &amount, &commitment, &0);
    assert_contract_error(result, QuickexError::ContractPaused);
}

#[test]
fn test_withdraw_fails_when_paused() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let admin = Address::generate(&env);
    let to = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"paused_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = to.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(&env, &client.address, &token, amount, commitment.clone(), 0);
    client.initialize(&admin);
    client.set_paused(&admin, &true);

    let result = client.try_withdraw(&token, &amount, &commitment, &to, &salt);
    assert_contract_error(result, QuickexError::ContractPaused);
}

#[test]
fn test_set_paused_by_admin() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin);

    // Admin pauses the contract
    client.set_paused(&admin, &true);
    assert!(client.is_paused());

    // Admin unpauses the contract
    client.set_paused(&admin, &false);
    assert!(!client.is_paused());
}

#[test]
fn test_set_paused_by_non_admin_fails() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin);

    // Non-admin tries to pause - should fail
    let result = client.try_set_paused(&non_admin, &true);
    assert_contract_error(result, QuickexError::Unauthorized);
}

#[test]
fn test_set_admin() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin);

    // Transfer admin rights
    client.set_admin(&admin, &new_admin);

    // Verify new admin is set
    assert_eq!(client.get_admin(), Some(new_admin.clone()));

    // Verify new admin can pause
    client.set_paused(&new_admin, &true);
    assert!(client.is_paused());
}

#[test]
fn test_event_snapshot_admin_changed_schema() {
    let (env, client) = setup();
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    client.initialize(&old_admin);
    client.set_admin(&old_admin, &new_admin);
}

#[test]
fn test_set_admin_by_non_admin_fails() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin);

    // Non-admin tries to transfer admin rights - should fail
    let result = client.try_set_admin(&non_admin, &new_admin);
    assert_contract_error(result, QuickexError::Unauthorized);
}

#[test]
fn test_old_admin_cannot_pause_after_transfer() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin);

    // Transfer admin rights
    client.set_admin(&admin, &new_admin);

    // Old admin tries to pause - should fail
    let result = client.try_set_paused(&admin, &true);
    assert_contract_error(result, QuickexError::Unauthorized);
}

#[test]
fn test_get_commitment_state_pending() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"test_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = owner.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(&env, &client.address, &token, amount, commitment.clone(), 0);

    let state = client.get_commitment_state(&commitment);
    assert_eq!(state, Some(EscrowStatus::Pending));
}

#[test]
fn test_get_commitment_state_spent() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"test_salt_spent");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = owner.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    // Create entry with Spent status
    let entry = EscrowEntry {
        token: token.clone(),
        amount,
        owner: owner.clone(),
        status: EscrowStatus::Spent,
        created_at: env.ledger().timestamp(),
        expires_at: 0,
    };

    env.as_contract(&client.address, || {
        let storage_commitment: Bytes = commitment.clone().into();
        put_escrow(&env, &storage_commitment, &entry);
    });

    let state = client.get_commitment_state(&commitment);
    assert_eq!(state, Some(EscrowStatus::Spent));
}

#[test]
fn test_get_commitment_state_not_found() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"nonexistent_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = owner.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    let state = client.get_commitment_state(&commitment);
    assert_eq!(state, None);
}

#[test]
fn test_verify_proof_view_valid() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"valid_proof_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = owner.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(&env, &client.address, &token, amount, commitment.clone(), 0);

    let is_valid = client.verify_proof_view(&amount, &salt, &owner);
    assert!(is_valid);
}

#[test]
fn test_verify_proof_view_wrong_amount() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let correct_amount: i128 = 1000;
    let wrong_amount: i128 = 500;
    let salt = Bytes::from_slice(&env, b"amount_test_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = owner.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &correct_amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(
        &env,
        &client.address,
        &token,
        correct_amount,
        commitment.clone(),
        0,
    );

    let is_valid = client.verify_proof_view(&wrong_amount, &salt, &owner);
    assert!(!is_valid);
}

#[test]
fn test_verify_proof_view_wrong_salt() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    let correct_salt = Bytes::from_slice(&env, b"correct_salt");
    let wrong_salt = Bytes::from_slice(&env, b"wrong_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = owner.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&correct_salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(&env, &client.address, &token, amount, commitment.clone(), 0);

    let is_valid = client.verify_proof_view(&amount, &wrong_salt, &owner);
    assert!(!is_valid);
}

#[test]
fn test_verify_proof_view_wrong_owner() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let correct_owner = Address::generate(&env);
    let wrong_owner = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"owner_test_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = correct_owner.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(&env, &client.address, &token, amount, commitment.clone(), 0);

    let is_valid = client.verify_proof_view(&amount, &salt, &wrong_owner);
    assert!(!is_valid);
}

#[test]
fn test_verify_proof_view_spent_commitment() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"spent_commitment_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = owner.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    // Create entry with Spent status
    let entry = EscrowEntry {
        token: token.clone(),
        amount,
        owner: owner.clone(),
        status: EscrowStatus::Spent,
        created_at: env.ledger().timestamp(),
        expires_at: 0,
    };

    let escrow_key = soroban_sdk::Symbol::new(&env, "escrow");
    env.as_contract(&client.address, || {
        env.storage()
            .persistent()
            .set(&(escrow_key, commitment.clone()), &entry);
    });

    let is_valid = client.verify_proof_view(&amount, &salt, &owner);
    assert!(!is_valid);
}

#[test]
fn test_verify_proof_view_nonexistent_commitment() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"nonexistent_proof_salt");

    let is_valid = client.verify_proof_view(&amount, &salt, &owner);
    assert!(!is_valid);
}

#[test]
fn test_get_escrow_details_found() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"details_test_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = owner.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(&env, &client.address, &token, amount, commitment.clone(), 0);

    // Privacy is off by default â€” any caller gets full data
    let caller = Address::generate(&env);
    let details = client.get_escrow_details(&commitment, &caller);
    assert!(details.is_some());

    let entry = details.unwrap();
    assert_eq!(entry.amount, Some(amount));
    assert_eq!(entry.token, token);
    assert_eq!(entry.status, EscrowStatus::Pending);
}

#[test]
fn test_get_escrow_details_not_found() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"not_found_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = owner.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    let caller = Address::generate(&env);
    let details = client.get_escrow_details(&commitment, &caller);
    assert!(details.is_none());
}

#[test]
fn test_get_escrow_details_spent_status() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"spent_details_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = owner.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    let entry = EscrowEntry {
        token: token.clone(),
        amount,
        owner: owner.clone(),
        status: EscrowStatus::Spent,
        created_at: env.ledger().timestamp(),
        expires_at: 0,
    };

    env.as_contract(&client.address, || {
        let storage_commitment: Bytes = commitment.clone().into();
        put_escrow(&env, &storage_commitment, &entry);
    });

    // Privacy off â€” caller is a stranger, still gets full data
    let caller = Address::generate(&env);
    let details = client.get_escrow_details(&commitment, &caller);
    assert!(details.is_some());

    let retrieved = details.unwrap();
    assert_eq!(retrieved.status, EscrowStatus::Spent);
    assert_eq!(retrieved.amount, Some(amount));
    assert_eq!(retrieved.token, token);
}
// ============================================================================
// Upgrade Tests
// ============================================================================

#[test]
fn test_upgrade_by_admin() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin);

    // Create a dummy WASM hash for testing
    let new_wasm_hash = BytesN::from_array(&env, &[0u8; 32]);

    // Admin calls upgrade - this tests the authorization logic
    // Note: In test environment, update_current_contract_wasm may fail
    // because the WASM hash doesn't exist, but the auth check should pass.
    // We use try_upgrade to verify auth passes (not Unauthorized error)
    let result = client.try_upgrade(&admin, &new_wasm_hash);

    // The call should NOT fail with Unauthorized (Contract error #2)
    // It may fail with a host error because the WASM doesn't exist in test env
    match result {
        Ok(_) => {} // Upgrade succeeded (unexpected in test env, but valid)
        Err(Ok(contract_error)) => {
            // This is a contract error - should NOT be Unauthorized
            assert_ne!(
                contract_error,
                QuickexError::Unauthorized,
                "Upgrade failed with Unauthorized error when admin called it"
            );
        }
        Err(Err(_host_error)) => {
            // Host error (e.g., WASM hash not found) - this is expected
            // The important thing is the auth check passed
        }
    }
}

#[test]
fn test_upgrade_by_non_admin_fails() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin);

    // Create a dummy WASM hash
    let new_wasm_hash = BytesN::from_array(&env, &[0u8; 32]);

    // Non-admin tries to upgrade - should fail with Unauthorized
    let result = client.try_upgrade(&non_admin, &new_wasm_hash);
    assert_contract_error(result, QuickexError::Unauthorized);
}

#[test]
fn test_upgrade_without_admin_initialized_fails() {
    let (env, client) = setup();
    let caller = Address::generate(&env);

    // Do NOT initialize admin
    let new_wasm_hash = BytesN::from_array(&env, &[0u8; 32]);

    // Try to upgrade without admin set - should fail with Unauthorized
    let result = client.try_upgrade(&caller, &new_wasm_hash);
    assert_contract_error(result, QuickexError::Unauthorized);
}

// ============================================================================
// Timeout & Refund Tests
// ============================================================================

#[test]
fn test_withdrawal_fails_after_expiry() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"expiry_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = to.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    // Set expiry to 100 seconds from now
    let now = env.ledger().timestamp();
    let expires_at = now + 100;
    setup_escrow(
        &env,
        &client.address,
        &token,
        amount,
        commitment.clone(),
        expires_at,
    );

    // Mint tokens to contract so it CAN pay if it were valid
    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&client.address, &amount);

    // 1. Withdrawal before expiry should work
    env.ledger().set_timestamp(now + 50);
    let res = client.try_withdraw(&token, &amount, &commitment, &to, &salt);
    assert!(res.is_ok());

    // Setup another one for the expiry test
    let salt2 = Bytes::from_slice(&env, b"expiry_salt_2");
    let mut data2 = Bytes::new(&env);
    data2.append(&to.clone().to_xdr(&env));
    data2.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data2.append(&salt2);
    let commitment2: BytesN<32> = env.crypto().sha256(&data2).into();
    setup_escrow(
        &env,
        &client.address,
        &token,
        amount,
        commitment2.clone(),
        expires_at,
    );
    token_client.mint(&client.address, &amount);

    // 2. Advance time past expiry
    env.ledger().set_timestamp(expires_at + 1);

    // Withdrawal should fail with EscrowExpired (error #13)
    let res = client.try_withdraw(&token, &amount, &commitment2, &to, &salt2);
    assert_eq!(res, Err(Ok(crate::errors::QuickexError::EscrowExpired)));
}

/// Regression suite: refund after expiry — golden path refund flow.
#[test]
fn test_refund_successful() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"refund_salt");

    // Use contract deposit to get owner correctly stored
    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&owner, &amount);

    let timeout = 100;
    let commitment = client.deposit(&token, &amount, &owner, &salt, &timeout);

    let start_time = env.ledger().timestamp();
    let expires_at = start_time + timeout;

    // Try refund early - should fail with EscrowNotExpired (error #14)
    env.ledger().set_timestamp(expires_at - 1);
    let res = client.try_refund(&commitment, &owner);
    assert_eq!(res, Err(Ok(crate::errors::QuickexError::EscrowNotExpired)));

    // Advance past expiry
    env.ledger().set_timestamp(expires_at);

    // Refund should work
    client.refund(&commitment, &owner);

    // Verify balance returned to owner
    let token_utils = token::Client::new(&env, &token);
    assert_eq!(token_utils.balance(&owner), amount);

    // Status should be Refunded
    assert_eq!(
        client.get_commitment_state(&commitment),
        Some(EscrowStatus::Refunded)
    );
}

#[test]
fn test_refund_unauthorized_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let thief = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"thief_salt");

    token::StellarAssetClient::new(&env, &token).mint(&owner, &amount);
    let commitment = client.deposit(&token, &amount, &owner, &salt, &100);

    // Advance past expiry
    env.ledger().set_timestamp(env.ledger().timestamp() + 101);

    // Thief tries to refund - should fail with InvalidOwner (error #15)
    let res = client.try_refund(&commitment, &thief);
    assert_eq!(res, Err(Ok(crate::errors::QuickexError::InvalidOwner)));
}

#[test]
fn test_double_refund_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"double_refund");

    token::StellarAssetClient::new(&env, &token).mint(&owner, &amount);
    let commitment = client.deposit(&token, &amount, &owner, &salt, &100);

    env.ledger().set_timestamp(env.ledger().timestamp() + 101);

    client.refund(&commitment, &owner);

    // Second refund attempt - should fail with AlreadySpent (error #9)
    let res = client.try_refund(&commitment, &owner);
    assert_eq!(res, Err(Ok(crate::errors::QuickexError::AlreadySpent)));
}

// ============================================================================
// Regression suite: single full-flow golden path (run after upgrades)
// ============================================================================

/// Regression suite: one test that runs the minimal golden path — create commitment,
/// deposit, toggle privacy, withdraw. Re-run with `cargo test regression_golden_path_full_flow`
/// after contract or SDK upgrades to ensure core flows still work.
#[test]
fn regression_golden_path_full_flow() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"regression_golden_salt");

    // 1. Create and verify commitment
    let commitment = client.create_amount_commitment(&to, &amount, &salt);
    assert!(client.verify_amount_commitment(&commitment, &to, &amount, &salt));

    // 2. Deposit: mint to `to` (owner) and deposit into escrow
    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&to, &amount);
    let committed = client.deposit(&token, &amount, &to, &salt, &0);
    assert_eq!(committed, commitment);
    assert_eq!(token_client.balance(&client.address), amount);

    // 3. Toggle privacy (must not break escrow or withdrawal)
    client.set_privacy(&to, &true);
    assert!(client.get_privacy(&to));
    client.set_privacy(&to, &false);
    assert!(!client.get_privacy(&to));

    // 4. Withdraw
    let ok = client.withdraw(&token, &amount, &commitment, &to, &salt);
    assert!(ok);
    assert_eq!(token_client.balance(&to), amount);
    assert_eq!(token_client.balance(&client.address), 0);
    assert_eq!(
        client.get_commitment_state(&commitment),
        Some(EscrowStatus::Spent)
    );
}
