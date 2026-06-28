use crate::{
    errors::QuickexError,
    events::{EVENT_SCHEMA_VERSION, EVENT_TOPIC_ADMIN},
    fee::{fee_from_bps_ceil, fee_from_bps_floor, MAX_FEE_BPS},
    types::{FeeConfig, PerAssetFeeConfig},
    QuickexContract, QuickexContractClient,
};
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger},
    token, Address, Bytes, ConversionError, Env, InvokeError, Map, Symbol, TryIntoVal, Val,
};

fn setup_test(
    env: &Env,
) -> (
    QuickexContractClient<'_>,
    Address,
    Address,
    Address,
    Address,
) {
    let admin = Address::generate(env);
    let platform_wallet = Address::generate(env);
    let owner = Address::generate(env);
    let recipient = Address::generate(env);

    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(env, &contract_id);

    client.initialize(&admin);

    (client, admin, platform_wallet, owner, recipient)
}

fn latest_contract_event(env: &Env, contract_id: &Address) -> (soroban_sdk::Vec<Val>, Val) {
    let all = env.events().all();
    let len = all.len();

    for i in (0..len).rev() {
        let event = all.get(i).unwrap();
        if event.0 == *contract_id {
            return (event.1, event.2);
        }
    }

    panic!("no contract event found for contract id")
}

fn event_data_map(env: &Env, data: Val) -> Map<Symbol, Val> {
    data.try_into_val(env).unwrap()
}

fn assert_contract_error<T>(
    result: Result<Result<T, ConversionError>, Result<QuickexError, InvokeError>>,
    expected: QuickexError,
) {
    match result {
        Err(Ok(actual)) => assert_eq!(actual, expected),
        _ => panic!("expected contract error"),
    }
}

#[test]
fn test_fee_admin() {
    let env = Env::default();
    let (client, admin, platform_wallet, _, _) = setup_test(&env);

    env.mock_all_auths();

    // Set fee config
    let fee_config = FeeConfig { fee_bps: 250 }; // 2.5%
    client.set_fee_config(&admin, &fee_config);

    assert_eq!(client.get_fee_config().fee_bps, 250);

    // Set platform wallet
    client.set_platform_wallet(&admin, &platform_wallet);
    assert_eq!(client.get_platform_wallet(), Some(platform_wallet));
}

#[test]
fn test_withdrawal_with_fee() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let (client, admin, platform_wallet, owner, _recipient) = setup_test(&env);

    // Setup token
    let token_admin = Address::generate(&env);
    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_id);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

    env.mock_all_auths();

    token_admin_client.mint(&owner, &10000);

    // Configure fees
    client.set_fee_config(&admin, &FeeConfig { fee_bps: 1000 }); // 10%
    client.set_platform_wallet(&admin, &platform_wallet);

    // Deposit
    let amount = 1000i128;
    let salt = Bytes::from_array(&env, &[1; 32]);
    let commitment = client.deposit(&token_id, &amount, &owner, &salt, &3600, &None);

    assert_eq!(token_client.balance(&owner), 9000);
    assert_eq!(token_client.balance(&client.address), 1000);

    // Withdraw (payout to recipient)
    // Salt must match the one used during deposit.
    // Commitment is recomputed from recipient, amount, and salt.
    // Wait, the commitment is recomputed from recipient during withdrawal in `escrow::withdraw`.
    // So the recipient must be the one whose address was used to create the commitment.
    // In `QuickexContract::deposit`, the commitment is created using `owner`.
    // Wait, let's check `escrow::deposit`:
    // `let commitment = commitment::create_amount_commitment(env, owner.clone(), amount, salt)?;`
    // And `escrow::withdraw`:
    // `let commitment = commitment::create_amount_commitment(env, to.clone(), amount, salt)?;`
    // This means the `owner` in `deposit` is the RECIPIENT who can withdraw.
    // Let me re-read `deposit`.
    // `pub fn deposit(..., owner: Address, salt: Bytes, ...)`
    // The `owner` is the one who can authorize the transfer AND whose address is in the commitment.
    // So if Alice deposits for Bob, Bob's address should be used in the commitment if Bob is to withdraw.
    // But `deposit` takes `amount` FROM `owner`.
    // Let's re-verify:
    // `owner.require_auth(); ... token_client.transfer(&owner, env.current_contract_address(), &amount);`
    // So `owner` is the depositor. And `withdraw` uses `to.require_auth()` and checks the commitment with `to`.
    // This means by default, only the depositor can withdraw to themselves using the commitment.
    // If they want someone else to withdraw, they'd need a different flow or use a different address in the commitment.
    // Actually, the commitment is `SHA256(owner || amount || salt)`.
    // If Alice deposits, the commitment is `SHA256(Alice || amount || salt)`. Only Alice can withdraw using this commitment.

    // Let's proceed with Alice (owner) withdrawing to herself.
    client.withdraw(&token_id, &amount, &commitment, &owner, &salt);

    // Fee is 10% of 1000 = 100.
    // Alice should get 1000 - 100 = 900.
    // Total balance for Alice: 9000 + 900 = 9900.
    assert_eq!(token_client.balance(&owner), 9900);
    assert_eq!(token_client.balance(&platform_wallet), 100);
    assert_eq!(token_client.balance(&client.address), 0);
}

#[test]
fn test_zero_fee() {
    let env = Env::default();
    let (client, admin, platform_wallet, owner, _) = setup_test(&env);

    let token_admin = Address::generate(&env);
    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_id);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

    env.mock_all_auths();

    token_admin_client.mint(&owner, &10000);

    // 0 Fee bps
    client.set_fee_config(&admin, &FeeConfig { fee_bps: 0 });
    client.set_platform_wallet(&admin, &platform_wallet);

    let amount = 1000i128;
    let salt = Bytes::from_array(&env, &[1; 32]);
    let commitment = client.deposit(&token_id, &amount, &owner, &salt, &3600, &None);

    client.withdraw(&token_id, &amount, &commitment, &owner, &salt);

    assert_eq!(token_client.balance(&owner), 10000);
    assert_eq!(token_client.balance(&platform_wallet), 0);
}

#[test]
fn test_set_fee_config_rejects_bps_above_max() {
    let env = Env::default();
    let (client, admin, _, _, _) = setup_test(&env);
    env.mock_all_auths();

    let result = client.try_set_fee_config(
        &admin,
        &FeeConfig {
            fee_bps: MAX_FEE_BPS + 1,
        },
    );
    assert_contract_error(result, QuickexError::InvalidAmount);
}

#[test]
fn test_set_fee_config_accepts_max_bps() {
    let env = Env::default();
    let (client, admin, _, _, _) = setup_test(&env);
    env.mock_all_auths();

    client.set_fee_config(
        &admin,
        &FeeConfig {
            fee_bps: MAX_FEE_BPS,
        },
    );
    assert_eq!(client.get_fee_config().fee_bps, MAX_FEE_BPS);
}

#[test]
fn test_set_per_asset_fee_rejects_bps_above_max() {
    let env = Env::default();
    let (client, admin, _, _, _) = setup_test(&env);
    let token = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    env.mock_all_auths();

    let result = client.try_set_per_asset_fee(
        &admin,
        &token,
        &PerAssetFeeConfig {
            fee_bps: MAX_FEE_BPS + 1,
            arbiter_bps: 0,
        },
    );
    assert_contract_error(result, QuickexError::InvalidAmount);

    let result = client.try_set_per_asset_fee(
        &admin,
        &token,
        &PerAssetFeeConfig {
            fee_bps: 100,
            arbiter_bps: MAX_FEE_BPS + 1,
        },
    );
    assert_contract_error(result, QuickexError::InvalidAmount);
}

#[test]
fn test_fee_rounding_floor_is_deterministic() {
    // 1 stroop at 1 bps → floor(0.0001) = 0
    assert_eq!(fee_from_bps_floor(1, 1), 0);
    // 9999 stroops at 1 bps → floor(0.9999) = 0
    assert_eq!(fee_from_bps_floor(9_999, 1), 0);
    // 10_000 stroops at 1 bps → exactly 1
    assert_eq!(fee_from_bps_floor(10_000, 1), 1);
    // 10_001 stroops at 1 bps → floor(1.0001) = 1
    assert_eq!(fee_from_bps_floor(10_001, 1), 1);
    // 333 stroops at 333 bps (3.33%) → floor(11.0889) = 11
    assert_eq!(fee_from_bps_floor(333, 333), 11);
    // Zero and negative amounts always yield zero fee.
    assert_eq!(fee_from_bps_floor(0, 500), 0);
    assert_eq!(fee_from_bps_floor(-100, 500), 0);
}

#[test]
fn test_fee_rounding_ceil_is_deterministic() {
    // 1 stroop at 1 bps → ceil(0.0001) = 1
    assert_eq!(fee_from_bps_ceil(1, 1), 1);
    // 9999 stroops at 1 bps → ceil(0.9999) = 1
    assert_eq!(fee_from_bps_ceil(9_999, 1), 1);
    // Exact multiples match floor.
    assert_eq!(fee_from_bps_ceil(10_000, 1), 1);
    assert_eq!(fee_from_bps_ceil(10_000, 1), fee_from_bps_floor(10_000, 1));
    // 333 stroops at 333 bps → ceil(11.0889) = 12
    assert_eq!(fee_from_bps_ceil(333, 333), 12);
    assert_eq!(fee_from_bps_ceil(0, 500), 0);
}

#[test]
fn test_fee_small_amount_edge_cases_on_withdrawal() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 1000);
    let (client, admin, platform_wallet, owner, _) = setup_test(&env);

    let token_admin = Address::generate(&env);
    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_id);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_id);
    env.mock_all_auths();

    token_admin_client.mint(&owner, &100_000);
    client.set_fee_config(&admin, &FeeConfig { fee_bps: 1 }); // 0.01%
    client.set_platform_wallet(&admin, &platform_wallet);

    // 1 stroop deposit: floor fee = 0, user gets full amount back.
    let tiny_amount: i128 = 1;
    let salt = Bytes::from_array(&env, &[2; 32]);
    let commitment = client.deposit(&token_id, &tiny_amount, &owner, &salt, &3600, &None);
    client.withdraw(&token_id, &tiny_amount, &commitment, &owner, &salt);
    assert_eq!(token_client.balance(&platform_wallet), 0);
    assert_eq!(token_client.balance(&owner), 100_000);

    // 9_999 stroops at 1 bps: fee floors to 0.
    let edge_amount: i128 = 9_999;
    let salt2 = Bytes::from_array(&env, &[3; 32]);
    let commitment2 = client.deposit(&token_id, &edge_amount, &owner, &salt2, &3600, &None);
    client.withdraw(&token_id, &edge_amount, &commitment2, &owner, &salt2);
    assert_eq!(token_client.balance(&platform_wallet), 0);
    assert_eq!(token_client.balance(&owner), 100_000);

    // 10_000 stroops at 1 bps: fee = 1.
    let threshold_amount: i128 = 10_000;
    let salt3 = Bytes::from_array(&env, &[4; 32]);
    let commitment3 = client.deposit(&token_id, &threshold_amount, &owner, &salt3, &3600, &None);
    client.withdraw(&token_id, &threshold_amount, &commitment3, &owner, &salt3);
    assert_eq!(token_client.balance(&platform_wallet), 1);
    assert_eq!(token_client.balance(&owner), 99_999);
}

#[test]
fn test_fee_extreme_values() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 1000);
    let (client, admin, platform_wallet, owner, _) = setup_test(&env);

    let token_admin = Address::generate(&env);
    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_id);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_id);
    env.mock_all_auths();

    let large_amount: i128 = i128::MAX / 2;
    token_admin_client.mint(&owner, &large_amount);

    client.set_fee_config(
        &admin,
        &FeeConfig {
            fee_bps: MAX_FEE_BPS,
        },
    );
    client.set_platform_wallet(&admin, &platform_wallet);

    let expected_fee = fee_from_bps_floor(large_amount, MAX_FEE_BPS);
    assert_eq!(expected_fee, large_amount);

    let salt = Bytes::from_array(&env, &[5; 32]);
    let commitment = client.deposit(&token_id, &large_amount, &owner, &salt, &3600, &None);
    client.withdraw(&token_id, &large_amount, &commitment, &owner, &salt);

    assert_eq!(token_client.balance(&platform_wallet), expected_fee);
    assert_eq!(token_client.balance(&owner), 0);
    assert_eq!(token_client.balance(&client.address), 0);
}

#[test]
fn test_fee_config_changed_event_emits_before_after_snapshot() {
    let env = Env::default();
    let (client, admin, _, _, _) = setup_test(&env);
    env.mock_all_auths();

    client.set_fee_config(&admin, &FeeConfig { fee_bps: 250 });
    client.set_fee_config(&admin, &FeeConfig { fee_bps: 500 });

    let (topics, data) = latest_contract_event(&env, &client.address);
    let t0: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
    let t1: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(t0, Symbol::new(&env, EVENT_TOPIC_ADMIN));
    assert_eq!(t1, Symbol::new(&env, "FeeConfigChanged"));

    let data_map = event_data_map(&env, data);
    let old_fee_bps: u32 = data_map
        .get(Symbol::new(&env, "old_fee_bps"))
        .unwrap()
        .try_into_val(&env)
        .unwrap();
    let fee_bps: u32 = data_map
        .get(Symbol::new(&env, "fee_bps"))
        .unwrap()
        .try_into_val(&env)
        .unwrap();
    let version: u32 = data_map
        .get(Symbol::new(&env, "schema_version"))
        .unwrap()
        .try_into_val(&env)
        .unwrap();

    assert_eq!(old_fee_bps, 250);
    assert_eq!(fee_bps, 500);
    assert_eq!(version, EVENT_SCHEMA_VERSION);
}

#[test]
fn test_fee_deterministic_across_assets() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 1000);
    let (client, admin, platform_wallet, owner, _) = setup_test(&env);
    env.mock_all_auths();

    let token_a = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    let token_b = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    let token_a_client = token::Client::new(&env, &token_a);
    let token_b_client = token::Client::new(&env, &token_b);
    token::StellarAssetClient::new(&env, &token_a).mint(&owner, &50_000);
    token::StellarAssetClient::new(&env, &token_b).mint(&owner, &50_000);

    client.set_fee_config(&admin, &FeeConfig { fee_bps: 333 });
    client.set_platform_wallet(&admin, &platform_wallet);
    client.set_per_asset_fee(
        &admin,
        &token_a,
        &PerAssetFeeConfig {
            fee_bps: 333,
            arbiter_bps: 0,
        },
    );

    let amount: i128 = 10_000;
    let expected_fee = fee_from_bps_floor(amount, 333);

    let salt_a = Bytes::from_array(&env, &[10; 32]);
    let commitment_a = client.deposit(&token_a, &amount, &owner, &salt_a, &3600, &None);
    client.withdraw(&token_a, &amount, &commitment_a, &owner, &salt_a);

    let salt_b = Bytes::from_array(&env, &[11; 32]);
    let commitment_b = client.deposit(&token_b, &amount, &owner, &salt_b, &3600, &None);
    client.withdraw(&token_b, &amount, &commitment_b, &owner, &salt_b);

    assert_eq!(token_a_client.balance(&platform_wallet), expected_fee);
    assert_eq!(token_b_client.balance(&platform_wallet), expected_fee);
    assert_eq!(token_a_client.balance(&owner), 50_000 - expected_fee);
    assert_eq!(token_b_client.balance(&owner), 50_000 - expected_fee);
}
