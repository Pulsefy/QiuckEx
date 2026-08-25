use crate::{
    batch::{batch_create, BatchCreateItem, MAX_BATCH_SIZE},
    errors::QuickexError,
    storage::get_escrow,
    QuickexContract, QuickexContractClient,
};

use soroban_sdk::{testutils::Address as _, token, Address, Bytes, Env, Vec};

fn setup<'a>() -> (Env, QuickexContractClient<'a>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    (env, client)
}

fn create_test_token(env: &Env) -> Address {
    env.register_stellar_asset_contract_v2(Address::generate(env))
        .address()
}

/// Test: batch exactly at MAX_BATCH_SIZE succeeds normally.
#[test]
fn test_batch_create_at_limit_succeeds() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);

    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&owner, &(MAX_BATCH_SIZE as i128 * 1_000));

    let mut items: Vec<BatchCreateItem> = Vec::new(&env);
    for i in 0..MAX_BATCH_SIZE {
        let mut escrow_id = Bytes::new(&env);
        escrow_id.push_back(i as u8);
        escrow_id.push_back(0);
        escrow_id.push_back(0);
        escrow_id.push_back(0);

        items.push_back(BatchCreateItem {
            escrow_id,
            owner: owner.clone(),
            token: token.clone(),
            amount: 1_000,
            expires_at: 0,
        });
    }

    let results = env
        .as_contract(&client.address, || batch_create(&env, &owner, items))
        .unwrap();
    assert_eq!(results.len(), MAX_BATCH_SIZE);
    for i in 0..MAX_BATCH_SIZE {
        let result = results.get(i).unwrap();
        assert!(result.success, "Item {} should succeed", i);
        assert_eq!(result.error_code, 0);
    }
}

/// Test: batch of MAX_BATCH_SIZE + 1 is rejected immediately with BatchSizeExceeded error.
/// Confirms zero operations from that batch were executed.
#[test]
fn test_batch_create_over_limit_rejects_immediately() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);

    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&owner, &((MAX_BATCH_SIZE + 1) as i128 * 1_000));

    let mut items: Vec<BatchCreateItem> = Vec::new(&env);
    for i in 0..=MAX_BATCH_SIZE {
        let mut escrow_id = Bytes::new(&env);
        escrow_id.push_back(i as u8);
        escrow_id.push_back(0);
        escrow_id.push_back(0);
        escrow_id.push_back(0);

        items.push_back(BatchCreateItem {
            escrow_id,
            owner: owner.clone(),
            token: token.clone(),
            amount: 1_000,
            expires_at: 0,
        });
    }

    let result = env.as_contract(&client.address, || batch_create(&env, &owner, items));
    assert_eq!(result, Err(QuickexError::BatchSizeExceeded));

    // Verify zero operations were executed
    env.as_contract(&client.address, || {
        for i in 0..=MAX_BATCH_SIZE {
            let mut escrow_id = Bytes::new(&env);
            escrow_id.push_back(i as u8);
            escrow_id.push_back(0);
            escrow_id.push_back(0);
            escrow_id.push_back(0);

            let entry = get_escrow(&env, &escrow_id);
            assert!(entry.is_none(), "No escrow should exist for item {}", i);
        }
    });
}

/// Test: within an at-or-under-limit batch, one operation partway through fails.
/// Confirms partial-success semantics: operations before the failing one are committed,
/// the failing one is not committed, and operations after are still executed.
#[test]
fn test_batch_create_mid_batch_failure_partial_success() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);

    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&owner, &10_000);

    // Create 5 items: items 0-2 will succeed, item 3 has zero amount (fails),
    // item 4 should still be executed (partial-success semantics)
    let mut items: Vec<BatchCreateItem> = Vec::new(&env);

    // Items 0-2: valid
    for i in 0..3 {
        let mut escrow_id = Bytes::new(&env);
        escrow_id.push_back(i as u8);
        escrow_id.push_back(0);
        escrow_id.push_back(0);
        escrow_id.push_back(0);

        items.push_back(BatchCreateItem {
            escrow_id,
            owner: owner.clone(),
            token: token.clone(),
            amount: 1_000,
            expires_at: 0,
        });
    }

    // Item 3: zero amount (will fail with InvalidAmount)
    {
        let mut escrow_id = Bytes::new(&env);
        escrow_id.push_back(3);
        escrow_id.push_back(0);
        escrow_id.push_back(0);
        escrow_id.push_back(0);

        items.push_back(BatchCreateItem {
            escrow_id,
            owner: owner.clone(),
            token: token.clone(),
            amount: 0, // Invalid amount
            expires_at: 0,
        });
    }

    // Item 4: valid and should be executed (partial-success semantics)
    {
        let mut escrow_id = Bytes::new(&env);
        escrow_id.push_back(4);
        escrow_id.push_back(0);
        escrow_id.push_back(0);
        escrow_id.push_back(0);

        items.push_back(BatchCreateItem {
            escrow_id,
            owner: owner.clone(),
            token: token.clone(),
            amount: 1_000,
            expires_at: 0,
        });
    }

    let results = env
        .as_contract(&client.address, || batch_create(&env, &owner, items))
        .unwrap();
    assert_eq!(results.len(), 5);

    // Items 0-2: success
    for i in 0..3 {
        let result = results.get(i).unwrap();
        assert!(result.success, "Item {} should succeed", i);
        assert_eq!(result.error_code, 0);
    }

    // Item 3: failure (zero amount)
    let result_3 = results.get(3).unwrap();
    assert!(!result_3.success);
    assert_eq!(result_3.error_code, QuickexError::InvalidAmount as u32);

    // Item 4: success (partial-success semantics: loop continues after failure)
    let result_4 = results.get(4).unwrap();
    assert!(result_4.success, "Item 4 should succeed");
    assert_eq!(result_4.error_code, 0);

    // Verify state: items 0-2 and 4 are committed, item 3 is not
    env.as_contract(&client.address, || {
        for i in 0..5u8 {
            let mut escrow_id = Bytes::new(&env);
            escrow_id.push_back(i);
            escrow_id.push_back(0);
            escrow_id.push_back(0);
            escrow_id.push_back(0);

            let entry = get_escrow(&env, &escrow_id);
            if i == 3 {
                assert!(entry.is_none(), "Item 3 should not be committed");
            } else {
                assert!(entry.is_some(), "Item {} should be committed", i);
            }
        }
    });
}
