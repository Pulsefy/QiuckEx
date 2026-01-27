#![cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

use crate::{
    storage::*,
    types::{EscrowEntry, EscrowStatus},
};

#[test]
fn test_escrow_storage() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        // Test basic escrow storage
        let commitment: Bytes = Bytes::from_array(&env, &[1u8; 32]);
        let token = Address::generate(&env);
        let owner = Address::generate(&env);
        let amount = 1000i128;
        let created_at = env.ledger().timestamp();

        let entry = EscrowEntry {
            token: token.clone(),
            amount,
            owner: owner.clone(),
            status: EscrowStatus::Pending,
            created_at,
        };

        // Test put_escrow
        put_escrow(&env, &commitment, &entry);

        // Test has_escrow
        assert!(has_escrow(&env, &commitment));

        // Test get_escrow
        let retrieved_entry = get_escrow(&env, &commitment).unwrap();
        assert_eq!(retrieved_entry.token, token);
        assert_eq!(retrieved_entry.amount, amount);
        assert_eq!(retrieved_entry.owner, owner);
        assert_eq!(retrieved_entry.status, EscrowStatus::Pending);
        assert_eq!(retrieved_entry.created_at, created_at);

        // Test non-existent key
        let non_existent_commitment: Bytes = Bytes::from_array(&env, &[2u8; 32]);
        assert!(!has_escrow(&env, &non_existent_commitment));
        assert!(get_escrow(&env, &non_existent_commitment).is_none());
    });
}

#[test]
fn test_escrow_status_update() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment: Bytes = Bytes::from_array(&env, &[1u8; 32]);
        let token = Address::generate(&env);
        let owner = Address::generate(&env);
        let amount = 1000i128;
        let created_at = env.ledger().timestamp();

        let mut entry = EscrowEntry {
            token: token.clone(),
            amount,
            owner: owner.clone(),
            status: EscrowStatus::Pending,
            created_at,
        };

        put_escrow(&env, &commitment, &entry);

        // Update status to Spent
        entry.status = EscrowStatus::Spent;
        put_escrow(&env, &commitment, &entry);

        let updated_entry = get_escrow(&env, &commitment).unwrap();
        assert_eq!(updated_entry.status, EscrowStatus::Spent);

        // Update status to Expired
        entry.status = EscrowStatus::Expired;
        put_escrow(&env, &commitment, &entry);

        let updated_entry = get_escrow(&env, &commitment).unwrap();
        assert_eq!(updated_entry.status, EscrowStatus::Expired);
    });
}

#[test]
fn test_escrow_counter() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        // Test initial counter value
        assert_eq!(get_escrow_counter(&env), 0);

        // Test incrementing counter
        assert_eq!(increment_escrow_counter(&env), 1);
        assert_eq!(get_escrow_counter(&env), 1);

        assert_eq!(increment_escrow_counter(&env), 2);
        assert_eq!(get_escrow_counter(&env), 2);

        assert_eq!(increment_escrow_counter(&env), 3);
        assert_eq!(get_escrow_counter(&env), 3);
    });
}

#[test]
fn test_admin_storage() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let admin = Address::generate(&env);

        // Test setting admin
        set_admin(&env, &admin);
        assert_eq!(get_admin(&env).unwrap(), admin);

        // Test updating admin
        let new_admin = Address::generate(&env);
        set_admin(&env, &new_admin);
        assert_eq!(get_admin(&env).unwrap(), new_admin);
    });
}

#[test]
fn test_paused_storage() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        // Test initial paused state
        assert!(!is_paused(&env));

        // Test setting paused to true
        set_paused(&env, true);
        assert!(is_paused(&env));

        // Test setting paused to false
        set_paused(&env, false);
        assert!(!is_paused(&env));
    });
}

#[test]
fn test_privacy_storage() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let account = Address::generate(&env);
        let privacy_level = 5u32;

        // Test setting privacy level
        set_privacy_level(&env, &account, privacy_level);
        assert_eq!(get_privacy_level(&env, &account).unwrap(), privacy_level);

        // Test updating privacy level
        let new_privacy_level = 10u32;
        set_privacy_level(&env, &account, new_privacy_level);
        assert_eq!(
            get_privacy_level(&env, &account).unwrap(),
            new_privacy_level
        );

        // Test privacy history
        add_privacy_history(&env, &account, 15u32);
        add_privacy_history(&env, &account, 20u32);
        add_privacy_history(&env, &account, 25u32);

        let history = get_privacy_history(&env, &account);
        assert_eq!(history.len(), 3);
        assert_eq!(history.get(0).unwrap(), 25u32);
        assert_eq!(history.get(1).unwrap(), 20u32);
        assert_eq!(history.get(2).unwrap(), 15u32);

        // Test non-existent privacy level
        let non_existent_account = Address::generate(&env);
        assert!(get_privacy_level(&env, &non_existent_account).is_none());
        assert_eq!(get_privacy_history(&env, &non_existent_account).len(), 0);
    });
}
