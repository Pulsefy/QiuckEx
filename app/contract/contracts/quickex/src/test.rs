use crate::{
    storage::put_escrow, EscrowEntry, EscrowStatus, QuickexContract, QuickexContractClient,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env,
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

fn create_test_token(env: &Env) -> Address {
    env.register_stellar_asset_contract_v2(Address::generate(env))
        .address()
}

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
#[should_panic]
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
    let _ = client.withdraw(&token, &amount, &commitment, &to, &salt);
}

#[test]
#[should_panic]
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
    let _ = client.withdraw(&token, &amount, &commitment, &to, &wrong_salt);
}

#[test]
#[should_panic]
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

    let _ = client.withdraw(&token, &wrong_amount, &commitment, &to, &salt);
}

#[test]
#[should_panic]
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

    let _ = client.withdraw(&token, &amount, &commitment, &to, &salt);
}

#[test]
#[should_panic]
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

    let _ = client.withdraw(&token, &amount, &commitment, &to, &salt);
}

#[test]
#[should_panic]
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
    let _ = client.withdraw(&token, &amount, &commitment, &to, &salt);
}

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
#[should_panic(expected = "Error(Contract, #1)")]
fn test_initialize_twice_fails() {
    let (env, client) = setup();
    let admin1 = Address::generate(&env);
    let admin2 = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin1);

    // Try to initialize again - should fail
    client.initialize(&admin2);
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
#[should_panic(expected = "Error(Contract, #2)")]
fn test_set_paused_by_non_admin_fails() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin);

    // Non-admin tries to pause - should fail
    client.set_paused(&non_admin, &true);
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
#[should_panic(expected = "Error(Contract, #2)")]
fn test_set_admin_by_non_admin_fails() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin);

    // Non-admin tries to transfer admin rights - should fail
    client.set_admin(&non_admin, &new_admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn test_old_admin_cannot_pause_after_transfer() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin);

    // Transfer admin rights
    client.set_admin(&admin, &new_admin);

    // Old admin tries to pause - should fail
    client.set_paused(&admin, &true);
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

    let details = client.get_escrow_details(&commitment);
    assert!(details.is_some());

    let entry = details.unwrap();
    assert_eq!(entry.amount, amount);
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

    let details = client.get_escrow_details(&commitment);
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

    let details = client.get_escrow_details(&commitment);
    assert!(details.is_some());

    let retrieved_entry = details.unwrap();
    assert_eq!(retrieved_entry.status, EscrowStatus::Spent);
    assert_eq!(retrieved_entry.amount, amount);
    assert_eq!(retrieved_entry.token, token);
}
// ============================================================================
// Upgrade Tests
// ============================================================================

#[test]
fn test_upgrade_by_admin() {
    use crate::errors::QuickexError;

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
#[should_panic(expected = "Error(Contract, #2)")]
fn test_upgrade_by_non_admin_fails() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);

    // Initialize admin
    client.initialize(&admin);

    // Create a dummy WASM hash
    let new_wasm_hash = BytesN::from_array(&env, &[0u8; 32]);

    // Non-admin tries to upgrade - should fail with Unauthorized
    client.upgrade(&non_admin, &new_wasm_hash);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn test_upgrade_without_admin_initialized_fails() {
    let (env, client) = setup();
    let caller = Address::generate(&env);

    // Do NOT initialize admin
    let new_wasm_hash = BytesN::from_array(&env, &[0u8; 32]);

    // Try to upgrade without admin set - should fail with Unauthorized
    client.upgrade(&caller, &new_wasm_hash);
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
