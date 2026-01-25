#![cfg(test)]

use crate::{QuickexContract, QuickexContractClient};
use soroban_sdk::{Address, Bytes, Env, testutils::Address as _};

fn setup<'a>() -> (Env, QuickexContractClient<'a>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    (env, client)
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
