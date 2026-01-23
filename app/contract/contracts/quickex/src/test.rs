#![cfg(test)]
use crate::{EscrowEntry, EscrowStatus, QuickexContract, QuickexContractClient};
use soroban_sdk::{Address, Bytes, BytesN, Env, testutils::Address as _, token, xdr::ToXdr};

fn setup<'a>() -> (Env, QuickexContractClient<'a>) {
    let env = Env::default();
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
        commitment: commitment.clone(),
        token: token.clone(),
        amount,
        status: EscrowStatus::Pending,
        depositor,
    };

    let escrow_key = soroban_sdk::Symbol::new(env, "escrow");

    env.as_contract(contract_id, || {
        env.storage()
            .persistent()
            .set(&(escrow_key, commitment), &entry);
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

    setup_escrow(&env, &client.address, &token, amount, commitment);

    env.mock_all_auths();

    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&client.address, &amount);

    let _ = client.withdraw(&to, &amount, &salt);
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

    let first_result = client.try_withdraw(&to, &amount, &salt);
    assert!(first_result.is_ok());
    assert_eq!(first_result.unwrap(), Ok(true));
    let _ = client.withdraw(&to, &amount, &salt);
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
    let _ = client.withdraw(&to, &amount, &wrong_salt);
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

    let _ = client.withdraw(&to, &wrong_amount, &salt);
}

#[test]
#[should_panic]
fn test_zero_amount_fails() {
    let (env, client) = setup();
    let to = Address::generate(&env);
    let amount: i128 = 0;
    let salt = Bytes::from_slice(&env, b"test_salt");

    env.mock_all_auths();

    let _ = client.withdraw(&to, &amount, &salt);
}

#[test]
#[should_panic]
fn test_negative_amount_fails() {
    let (env, client) = setup();
    let to = Address::generate(&env);
    let amount: i128 = -100;
    let salt = Bytes::from_slice(&env, b"test_salt");

    env.mock_all_auths();

    let _ = client.withdraw(&to, &amount, &salt);
}

#[test]
#[should_panic]
fn test_nonexistent_commitment_fails() {
    let (env, client) = setup();
    let to = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"nonexistent");

    env.mock_all_auths();
    let _ = client.withdraw(&to, &amount, &salt);
}

#[test]
fn test_enable_and_check_privacy() {
    let (env, client) = setup();

    let account1 = Address::generate(&env);
    let account2 = Address::generate(&env);

    assert!(client.enable_privacy(&account1, &2));
    assert!(client.enable_privacy(&account2, &3));

    assert_eq!(client.privacy_status(&account1), Some(2));
    assert_eq!(client.privacy_status(&account2), Some(3));

    let account3 = Address::generate(&env);
    assert_eq!(client.privacy_status(&account3), None);
}

#[test]
fn test_privacy_history() {
    let (env, client) = setup();

    let account = Address::generate(&env);

    client.enable_privacy(&account, &1);
    client.enable_privacy(&account, &2);
    client.enable_privacy(&account, &3);

    let history = client.privacy_history(&account);

    assert_eq!(history.len(), 3);
    assert_eq!(history.get(0).unwrap(), 3);
    assert_eq!(history.get(1).unwrap(), 2);
    assert_eq!(history.get(2).unwrap(), 1);
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
fn test_storage_isolation() {
    let (env, client) = setup();

    let account1 = Address::generate(&env);
    let account2 = Address::generate(&env);

    client.enable_privacy(&account1, &1);
    client.enable_privacy(&account2, &2);

    assert_eq!(client.privacy_status(&account1), Some(1));
    assert_eq!(client.privacy_status(&account2), Some(2));
}

// #![cfg(test)]

// use crate::{QuickSilverContract, QuickSilverContractClient};
// use soroban_sdk::{Env, Address};

// #[test]
// fn test_enable_and_check_privacy() {
//     let env = Env::default();
//     let contract_id = env.register(QuickSilverContract);  // Fixed: use register() not register_contract()
//     let client = QuickSilverContractClient::new(&env, &contract_id);

//     // Create test accounts
//     let account1 = Address::generate(&env);  // Fixed: use generate() not random()
//     let account2 = Address::generate(&env);

//     // Test enabling privacy
//     assert!(client.enable_privacy(&account1, &2));
//     assert!(client.enable_privacy(&account2, &3));

//     // Test checking privacy status
//     let status1 = client.privacy_status(&account1);
//     let status2 = client.privacy_status(&account2);

//     assert_eq!(status1, Some(2));
//     assert_eq!(status2, Some(3));

//     // Test non-existent account
//     let account3 = Address::generate(&env);
//     let status3 = client.privacy_status(&account3);
//     assert_eq!(status3, None);
// }

// #[test]
// fn test_privacy_history() {
//     let env = Env::default();
//     let contract_id = env.register(QuickSilverContract);
//     let client = QuickSilverContractClient::new(&env, &contract_id);

//     let account = Address::generate(&env);

//     // Enable privacy multiple times
//     assert!(client.enable_privacy(&account, &1));
//     assert!(client.enable_privacy(&account, &2));
//     assert!(client.enable_privacy(&account, &3));

//     // Check history
//     let history = client.privacy_history(&account);
//     assert_eq!(history.len(), 3);
//     assert_eq!(history.get(0).unwrap(), 3); // Most recent first
//     assert_eq!(history.get(1).unwrap(), 2);
//     assert_eq!(history.get(2).unwrap(), 1);
// }

// #[test]
// fn test_create_escrow() {
//     let env = Env::default();
//     let contract_id = env.register(QuickSilverContract);
//     let client = QuickSilverContractClient::new(&env, &contract_id);

//     let from = Address::generate(&env);
//     let to = Address::generate(&env);
//     let amount = 1000;

//     let escrow_id = client.create_escrow(&from, &to, &amount);

//     // Verify escrow ID is generated (basic validation)
//     assert!(escrow_id > 0);
// }

// #[test]
// fn test_health_check() {
//     let env = Env::default();
//     let contract_id = env.register(QuickSilverContract);
//     let client = QuickSilverContractClient::new(&env, &contract_id);

//     assert!(client.health_check());
// }

// #[test]
// fn test_storage_isolation() {
//     let env = Env::default();
//     let contract_id = env.register(QuickSilverContract);
//     let client = QuickSilverContractClient::new(&env, &contract_id);

//     let account1 = Address::generate(&env);
//     let account2 = Address::generate(&env);

//     // Set different privacy levels
//     client.enable_privacy(&account1, &1);
//     client.enable_privacy(&account2, &2);

//     // Verify isolation
//     assert_eq!(client.privacy_status(&account1), Some(1));
//     assert_eq!(client.privacy_status(&account2), Some(2));
// }

// #![cfg(test)]

// use crate::{QuickSilverContract, QuickSilverContractClient};
// use soroban_sdk::{Env, Address, Symbol, testutils::Address as _};
// use super::*;

// #[test]
// fn test_enable_and_check_privacy() {
//     let env = Env::default();
//     let contract_id = env.register_contract(None, QuickSilverContract);
//     let client = QuickSilverContractClient::new(&env, &contract_id);

//     // Create test accounts
//     let account1 = Address::random(&env);
//     let account2 = Address::random(&env);

//     // Test enabling privacy
//     assert!(client.enable_privacy(&account1, &2));
//     assert!(client.enable_privacy(&account2, &3));

//     // Test checking privacy status
//     let status1 = client.privacy_status(&account1);
//     let status2 = client.privacy_status(&account2);

//     assert_eq!(status1, Some(2));
//     assert_eq!(status2, Some(3));

//     // Test non-existent account
//     let account3 = Address::random(&env);
//     let status3 = client.privacy_status(&account3);
//     assert_eq!(status3, None);
// }

// #[test]
// fn test_privacy_history() {
//     let env = Env::default();
//     let contract_id = env.register_contract(None, QuickSilverContract);
//     let client = QuickSilverContractClient::new(&env, &contract_id);

//     let account = Address::random(&env);

//     // Enable privacy multiple times
//     assert!(client.enable_privacy(&account, &1));
//     assert!(client.enable_privacy(&account, &2));
//     assert!(client.enable_privacy(&account, &3));

//     // Check history
//     let history = client.privacy_history(&account);
//     assert_eq!(history.len(), 3);
//     assert_eq!(history.get(0).unwrap(), 3); // Most recent first
//     assert_eq!(history.get(1).unwrap(), 2);
//     assert_eq!(history.get(2).unwrap(), 1);
// }

// #[test]
// fn test_create_escrow() {
//     let env = Env::default();
//     let contract_id = env.register_contract(None, QuickSilverContract);
//     let client = QuickSilverContractClient::new(&env, &contract_id);

//     let from = Address::random(&env);
//     let to = Address::random(&env);
//     let amount = 1000;

//     let escrow_id = client.create_escrow(&from, &to, &amount);

//     // Verify escrow ID is generated (basic validation)
//     assert!(escrow_id > 0);
// }

// #[test]
// fn test_health_check() {
//     let env = Env::default();
//     let contract_id = env.register_contract(None, QuickSilverContract);
//     let client = QuickSilverContractClient::new(&env, &contract_id);

//     assert!(client.health_check());
// }

// #[test]
// fn test_storage_isolation() {
//     let env = Env::default();
//     let contract_id = env.register_contract(None, QuickSilverContract);
//     let client = QuickSilverContractClient::new(&env, &contract_id);

//     let account1 = Address::random(&env);
//     let account2 = Address::random(&env);

//     // Set different privacy levels
//     client.enable_privacy(&account1, &1);
//     client.enable_privacy(&account2, &2);

//     // Verify isolation
//     assert_eq!(client.privacy_status(&account1), Some(1));
//     assert_eq!(client.privacy_status(&account2), Some(2));
// }
