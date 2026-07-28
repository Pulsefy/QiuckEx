#![cfg(test)]
extern crate std;

use crate::{QuickexContract, QuickexContractClient};
use soroban_sdk::{testutils::Address as _, Address, Env};

#[test]
fn test_hook_allowlist() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    let hook_contract = Address::generate(&env);

    // Unapproved hook should fail registration
    let res = client.try_register_hook(&hook_contract);
    assert!(res.is_err());

    // Admin approves hook
    client.set_hook_approved(&admin, &hook_contract, &true);
    assert!(client.is_hook_approved(&hook_contract));

    // Now registration should succeed
    client.register_hook(&hook_contract);
    let hooks = client.get_registered_hooks();
    assert!(hooks.contains(hook_contract.clone()));

    // Unregister
    client.unregister_hook(&hook_contract);

    // Disapprove
    client.set_hook_approved(&admin, &hook_contract, &false);
    assert!(!client.is_hook_approved(&hook_contract));

    // Registration should fail again
    let res = client.try_register_hook(&hook_contract);
    assert!(res.is_err());
}
