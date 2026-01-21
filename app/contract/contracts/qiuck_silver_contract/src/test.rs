#![cfg(test)]

use soroban_sdk::{
    testutils::Address as _,
    Address,
    Env,
};

use crate::{QuickSilverContract, QuickSilverContractClient};

fn setup<'a>() -> (Env, QuickSilverContractClient<'a>) {
    let env = Env::default();
    let contract_id = env.register(QuickSilverContract, ());
    let client = QuickSilverContractClient::new(&env, &contract_id);
    (env, client)
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