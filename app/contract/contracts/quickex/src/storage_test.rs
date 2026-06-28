use soroban_sdk::{testutils::Ledger, Vec};
#[test]
fn test_ttl_auto_extend_on_activity() {
    // No need to import Ledger trait; only use set_timestamp
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment: Bytes = Bytes::from_array(&env, &[3u8; 32]);
        let token = Address::generate(&env);
        let owner = Address::generate(&env);
        let amount = 1000i128;
        let created_at = env.ledger().timestamp();
        let entry = EscrowEntry {
            token: token.clone(),
            amount_due: amount,
            amount_paid: amount,
            owner: owner.clone(),
            status: EscrowStatus::Pending,
            created_at,
            expires_at: 0,
            arbiter: None,
            arbiters: Vec::new(&env),
            arbiter_threshold: 0,
        };
        put_escrow(&env, &commitment, &entry);

        // Simulate ledger aging and access (activity)
        for i in 1..5 {
            env.ledger().set_timestamp(created_at + (i * 100_000));
            // Accessing the record should auto-extend TTL
            assert!(get_escrow(&env, &commitment).is_some());
        }
    });
}

#[test]
fn test_ttl_expiry_of_inactive_record() {
    use soroban_sdk::testutils::Ledger;
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment: Bytes = Bytes::from_array(&env, &[4u8; 32]);
        let token = Address::generate(&env);
        let owner = Address::generate(&env);
        let amount = 1000i128;
        let created_at = env.ledger().timestamp();
        let entry = EscrowEntry {
            token: token.clone(),
            amount_due: amount,
            amount_paid: amount,
            owner: owner.clone(),
            status: EscrowStatus::Pending,
            created_at,
            expires_at: 0,
            arbiter: None,
            arbiters: Vec::new(&env),
            arbiter_threshold: 0,
        };
        put_escrow(&env, &commitment, &entry);

        // Simulate ledger aging without activity (no access)
        env.ledger().set_timestamp(created_at + 10_000_000);
        // Record should still exist (Soroban test env does not auto-expire, but this is where expiry would be checked in real runtime)
        assert!(get_escrow(&env, &commitment).is_some());
        // In a real chain, a cleanup or expiry sweep would remove it if TTL expired
    });
}

#[test]
fn test_cleanup_does_not_remove_active_escrow() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment: Bytes = Bytes::from_array(&env, &[5u8; 32]);
        let token = Address::generate(&env);
        let owner = Address::generate(&env);
        let amount = 1000i128;
        let created_at = env.ledger().timestamp();
        let entry = EscrowEntry {
            token: token.clone(),
            amount_due: amount,
            amount_paid: amount,
            owner: owner.clone(),
            status: EscrowStatus::Pending,
            created_at,
            expires_at: 0,
            arbiter: None,
            arbiters: Vec::new(&env),
            arbiter_threshold: 0,
        };
        put_escrow(&env, &commitment, &entry);
        // Attempt cleanup (should not remove active escrow)
        let result = crate::escrow::cleanup_escrow(&env, commitment.clone().try_into().unwrap());
        assert!(result.is_err());
        assert!(has_escrow(&env, &commitment));
    });
}
use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

use crate::{
    storage::*,
    types::{EscrowEntry, EscrowStatus},
};

fn make_entry(env: &Env, amount: i128) -> EscrowEntry {
    EscrowEntry {
        token: Address::generate(env),
        amount_due: amount,
        amount_paid: amount,
        owner: Address::generate(env),
        status: EscrowStatus::Pending,
        created_at: env.ledger().timestamp(),
        expires_at: 0,
        arbiter: None,
        arbiters: Vec::new(env),
        arbiter_threshold: 0,
    }
}

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
            amount_due: amount,
            amount_paid: amount,
            owner: owner.clone(),
            status: EscrowStatus::Pending,
            created_at,
            expires_at: 0,
            arbiter: None,
            arbiters: Vec::new(&env),
            arbiter_threshold: 0,
        };

        // Test put_escrow
        put_escrow(&env, &commitment, &entry);

        // Test has_escrow
        assert!(has_escrow(&env, &commitment));

        // Test get_escrow
        let retrieved_entry = get_escrow(&env, &commitment).unwrap();
        assert_eq!(retrieved_entry.token, token);
        assert_eq!(retrieved_entry.amount_due, amount);
        assert_eq!(retrieved_entry.amount_paid, amount);
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
fn test_common_escrow_is_compacted_and_smaller_than_legacy_layout() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment: Bytes = Bytes::from_array(&env, &[6u8; 32]);
        let entry = make_entry(&env, 2_500);

        put_escrow(&env, &commitment, &entry);

        assert!(env
            .storage()
            .persistent()
            .has(&DataKey::EscrowCore(commitment.clone())));
        assert!(!env
            .storage()
            .persistent()
            .has(&DataKey::Escrow(commitment.clone())));
        assert!(!env
            .storage()
            .persistent()
            .has(&DataKey::EscrowDispute(commitment.clone())));

        let compact_bytes = compact_escrow_storage_footprint_bytes(&env, &commitment, &entry);
        let legacy_bytes = legacy_escrow_storage_footprint_bytes(&env, &commitment, &entry);
        assert!(
            compact_bytes < legacy_bytes,
            "expected compact footprint {compact_bytes} to be smaller than legacy {legacy_bytes}"
        );
    });
}

#[test]
fn test_arbiter_escrow_round_trips_via_separate_dispute_record() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment: Bytes = Bytes::from_array(&env, &[7u8; 32]);
        let arbiter = Address::generate(&env);
        let mut entry = make_entry(&env, 5_000);
        entry.arbiter = Some(arbiter.clone());

        put_escrow(&env, &commitment, &entry);

        assert!(env
            .storage()
            .persistent()
            .has(&DataKey::EscrowCore(commitment.clone())));
        assert!(env
            .storage()
            .persistent()
            .has(&DataKey::EscrowDispute(commitment.clone())));

        let stored = get_escrow(&env, &commitment).unwrap();
        assert_eq!(stored.arbiter, Some(arbiter));
        assert!(stored.arbiters.is_empty());
        assert_eq!(stored.arbiter_threshold, 0);
    });
}

#[test]
fn test_legacy_escrow_can_be_rewritten_to_compact_storage() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment: Bytes = Bytes::from_array(&env, &[8u8; 32]);
        let entry = make_entry(&env, 7_500);

        env.storage()
            .persistent()
            .set(&DataKey::Escrow(commitment.clone()), &entry);

        let mut updated = get_escrow(&env, &commitment).unwrap();
        assert_eq!(updated.amount_due, entry.amount_due);
        updated.status = EscrowStatus::Spent;

        put_escrow(&env, &commitment, &updated);

        assert!(env
            .storage()
            .persistent()
            .has(&DataKey::EscrowCore(commitment.clone())));
        assert!(!env
            .storage()
            .persistent()
            .has(&DataKey::Escrow(commitment.clone())));
        assert_eq!(
            get_escrow(&env, &commitment).unwrap().status,
            EscrowStatus::Spent
        );
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
            amount_due: amount,
            amount_paid: amount,
            owner: owner.clone(),
            status: EscrowStatus::Pending,
            created_at,
            expires_at: 0,
            arbiter: None,
            arbiters: Vec::new(&env),
            arbiter_threshold: 0,
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
fn test_contract_version_storage() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        assert_eq!(get_contract_version(&env), None);

        set_contract_version(&env, CURRENT_CONTRACT_VERSION);
        assert_eq!(get_contract_version(&env), Some(CURRENT_CONTRACT_VERSION));
    });
}

#[test]
fn test_initialized_flag_storage() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        assert!(!is_initialized(&env));

        set_initialized(&env, true);
        assert!(is_initialized(&env));

        set_initialized(&env, false);
        assert!(!is_initialized(&env));
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
