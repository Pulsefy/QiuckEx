#![cfg(test)]

use soroban_sdk::{Address, Bytes, Env, testutils::Address as _};

use crate::{QuickexContract, QuickexContractClient};

fn setup<'a>() -> (Env, QuickexContractClient<'a>) {
    let env = Env::default();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
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

// ============================================================================
// COMMITMENT TESTS
// ============================================================================

#[test]
fn test_create_and_verify_commitment_success() {
    let (env, client) = setup();
    
    let owner = Address::generate(&env);
    let amount = 1_000_000i128;
    let salt = Bytes::from_slice(&env, &[1, 2, 3, 4, 5]);

    let commitment = client.create_amount_commitment(&owner, &amount, &salt);

    // Commitment should be 32 bytes (SHA256)
    assert_eq!(commitment.len(), 32);

    // Verification with same values should succeed
    assert!(client.verify_amount_commitment(&commitment, &owner, &amount, &salt));
}

#[test]
fn test_verify_commitment_with_tampered_amount() {
    let (env, client) = setup();

    let owner = Address::generate(&env);
    let amount = 1_000_000i128;
    let salt = Bytes::from_slice(&env, &[1, 2, 3, 4, 5]);

    let commitment = client.create_amount_commitment(&owner, &amount, &salt);

    // Verification with different amount should fail
    assert!(!client.verify_amount_commitment(&commitment, &owner, &(amount + 1), &salt));
    assert!(!client.verify_amount_commitment(&commitment, &owner, &(amount - 1), &salt));
}

#[test]
fn test_verify_commitment_with_tampered_salt() {
    let (env, client) = setup();

    let owner = Address::generate(&env);
    let amount = 1_000_000i128;
    let salt = Bytes::from_slice(&env, &[1, 2, 3, 4, 5]);

    let commitment = client.create_amount_commitment(&owner, &amount, &salt);

    // Verification with different salt should fail
    let tampered_salt = Bytes::from_slice(&env, &[1, 2, 3, 4, 6]);
    assert!(!client.verify_amount_commitment(&commitment, &owner, &amount, &tampered_salt));

    let empty_salt = Bytes::new(&env);
    assert!(!client.verify_amount_commitment(&commitment, &owner, &amount, &empty_salt));
}

#[test]
fn test_verify_commitment_with_different_owner() {
    let (env, client) = setup();

    let owner1 = Address::generate(&env);
    let owner2 = Address::generate(&env);
    let amount = 1_000_000i128;
    let salt = Bytes::from_slice(&env, &[1, 2, 3, 4, 5]);

    let commitment = client.create_amount_commitment(&owner1, &amount, &salt);

    // Verification with different owner should fail
    assert!(!client.verify_amount_commitment(&commitment, &owner2, &amount, &salt));
}

#[test]
fn test_commitment_zero_amount() {
    let (env, client) = setup();

    let owner = Address::generate(&env);
    let amount = 0i128;
    let salt = Bytes::from_slice(&env, &[42]);

    let commitment = client.create_amount_commitment(&owner, &amount, &salt);

    assert_eq!(commitment.len(), 32);
    assert!(client.verify_amount_commitment(&commitment, &owner, &amount, &salt));
}

#[test]
fn test_commitment_empty_salt() {
    let (env, client) = setup();

    let owner = Address::generate(&env);
    let amount = 500i128;
    let salt = Bytes::new(&env);

    let commitment = client.create_amount_commitment(&owner, &amount, &salt);

    assert_eq!(commitment.len(), 32);
    assert!(client.verify_amount_commitment(&commitment, &owner, &amount, &salt));
}

#[test]
fn test_commitment_large_amount() {
    let (env, client) = setup();

    let owner = Address::generate(&env);
    let amount = i128::MAX;
    let salt = Bytes::from_slice(&env, &[99, 88, 77]);

    let commitment = client.create_amount_commitment(&owner, &amount, &salt);

    assert_eq!(commitment.len(), 32);
    assert!(client.verify_amount_commitment(&commitment, &owner, &amount, &salt));
}

#[test]
fn test_commitment_deterministic_hashing() {
    let (env, client) = setup();

    let owner = Address::generate(&env);
    let amount = 2_500_000i128;
    let salt = Bytes::from_slice(&env, &[11, 22, 33, 44]);

    let commitment1 = client.create_amount_commitment(&owner, &amount, &salt);
    let commitment2 = client.create_amount_commitment(&owner, &amount, &salt);

    // Same inputs should produce identical commitments
    assert_eq!(commitment1, commitment2);
}

#[test]
fn test_commitment_multiple_owners_different_hashes() {
    let (env, client) = setup();

    let owner1 = Address::generate(&env);
    let owner2 = Address::generate(&env);
    let amount = 1_000_000i128;
    let salt = Bytes::from_slice(&env, &[5, 6, 7, 8]);

    let commitment1 = client.create_amount_commitment(&owner1, &amount, &salt);
    let commitment2 = client.create_amount_commitment(&owner2, &amount, &salt);

    // Different owners should produce different commitments
    assert_ne!(commitment1, commitment2);
}

#[test]
fn test_commitment_different_amounts_different_hashes() {
    let (env, client) = setup();

    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, &[3, 4, 5, 6]);

    let commitment1 = client.create_amount_commitment(&owner, &1000i128, &salt);
    let commitment2 = client.create_amount_commitment(&owner, &2000i128, &salt);

    // Different amounts should produce different commitments
    assert_ne!(commitment1, commitment2);
}

#[test]
fn test_commitment_different_salts_different_hashes() {
    let (env, client) = setup();

    let owner = Address::generate(&env);
    let amount = 1_000_000i128;

    let salt1 = Bytes::from_slice(&env, &[1, 2, 3]);
    let salt2 = Bytes::from_slice(&env, &[4, 5, 6]);

    let commitment1 = client.create_amount_commitment(&owner, &amount, &salt1);
    let commitment2 = client.create_amount_commitment(&owner, &amount, &salt2);

    // Different salts should produce different commitments
    assert_ne!(commitment1, commitment2);
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
