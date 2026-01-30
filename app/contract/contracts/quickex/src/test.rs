#![cfg(test)]
use crate::{
    storage::put_escrow, EscrowEntry, EscrowStatus, QuickexContract, QuickexContractClient,
};
use soroban_sdk::{testutils::Address as _, token, xdr::ToXdr, Address, Bytes, BytesN, Env};

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
) {
    let depositor = Address::generate(env);

    let entry = EscrowEntry {
        token: token.clone(),
        amount,
        owner: depositor,
        status: EscrowStatus::Pending,
        created_at: env.ledger().timestamp(),
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

    setup_escrow(&env, &client.address, &token, amount, commitment.clone());

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

    setup_escrow(&env, &client.address, &token, amount, commitment.clone());

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

    setup_escrow(&env, &client.address, &token, amount, commitment.clone());

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

    client.deposit_with_commitment(&user, &token_id, &500, &commitment);

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

    setup_escrow(&env, &client.address, &token, amount, commitment.clone());

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

    setup_escrow(&env, &client.address, &token, amount, commitment.clone());

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

    setup_escrow(&env, &client.address, &token, amount, commitment.clone());

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

    setup_escrow(&env, &client.address, &token, amount, commitment.clone());

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

    setup_escrow(&env, &client.address, &token, amount, commitment.clone());

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
