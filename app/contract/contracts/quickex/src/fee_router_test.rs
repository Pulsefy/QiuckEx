use crate::{
    errors::QuickexError,
    types::{OracleFeeConfig, PerAssetFeeConfig},
    EscrowStatus, QuickexContract, QuickexContractClient,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, Bytes, Env,
};

fn setup<'a>() -> (Env, QuickexContractClient<'a>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|li| li.timestamp = 1_000);

    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    (env, client, admin)
}

fn create_token(env: &Env) -> Address {
    env.register_stellar_asset_contract_v2(Address::generate(env))
        .address()
}

#[test]
fn test_fee_router_per_asset_overrides_global_across_assets() {
    let (env, client, admin) = setup();

    // "XLM" and "SAC" are both represented as token contract addresses in Soroban.
    let xlm_token = create_token(&env);
    let sac_token = create_token(&env);

    let user = Address::generate(&env);
    let collector = Address::generate(&env);

    let xlm_admin = token::StellarAssetClient::new(&env, &xlm_token);
    let sac_admin = token::StellarAssetClient::new(&env, &sac_token);
    let xlm_client = token::Client::new(&env, &xlm_token);
    let sac_client = token::Client::new(&env, &sac_token);

    xlm_admin.mint(&user, &10_000);
    sac_admin.mint(&user, &10_000);

    // Global fee = 5%.
    client.set_fee_config(&admin, &crate::types::FeeConfig { fee_bps: 500 });
    client.set_platform_wallet(&admin, &collector);

    // Per-asset override for XLM token = 10%.
    client.set_per_asset_fee(
        &admin,
        &xlm_token,
        &PerAssetFeeConfig {
            fee_bps: 1_000,
            arbiter_bps: 0,
        },
    );

    // Withdraw XLM path: fee should use per-asset 10%.
    let xlm_amount: i128 = 1_000;
    let xlm_salt = Bytes::from_slice(&env, b"fee_router_xlm_salt");
    let xlm_commitment = client.deposit(
        &xlm_token,
        &xlm_amount,
        &user,
        &xlm_salt,
        &0,
        &None,
        &0u64,
        &u64::MAX,
    );
    client.withdraw(
        &xlm_token,
        &xlm_amount,
        &xlm_commitment,
        &user,
        &xlm_salt,
        &0u64,
        &u64::MAX,
    );

    // Withdraw SAC path: fee should use global 5%.
    let sac_amount: i128 = 1_000;
    let sac_salt = Bytes::from_slice(&env, b"fee_router_sac_salt");
    let sac_commitment = client.deposit(
        &sac_token,
        &sac_amount,
        &user,
        &sac_salt,
        &0,
        &None,
        &1u64,
        &u64::MAX,
    );
    client.withdraw(
        &sac_token,
        &sac_amount,
        &sac_commitment,
        &user,
        &sac_salt,
        &1u64,
        &u64::MAX,
    );

    // Expected fees: XLM 100 + SAC 50 = 150 to collector.
    assert_eq!(xlm_client.balance(&collector), 100);
    assert_eq!(sac_client.balance(&collector), 50);

    // User received net payout per token and no escrow balance remains in contract.
    assert_eq!(xlm_client.balance(&client.address), 0);
    assert_eq!(sac_client.balance(&client.address), 0);

    // Sanity check statuses are terminal and correct.
    assert_eq!(
        client.get_commitment_state(&xlm_commitment),
        Some(EscrowStatus::Spent)
    );
    assert_eq!(
        client.get_commitment_state(&sac_commitment),
        Some(EscrowStatus::Spent)
    );
}

#[test]
fn test_fee_router_dispute_with_optional_arbiter_split() {
    let (env, client, admin) = setup();

    let token_id = create_token(&env);
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);
    let arbiter = Address::generate(&env);
    let collector = Address::generate(&env);

    let token_admin = token::StellarAssetClient::new(&env, &token_id);
    let token_client = token::Client::new(&env, &token_id);

    token_admin.mint(&owner, &10_000);

    client.set_platform_wallet(&admin, &collector);
    client.set_per_asset_fee(
        &admin,
        &token_id,
        &PerAssetFeeConfig {
            fee_bps: 1_000,     // 10% total fee
            arbiter_bps: 2_000, // 20% of fee to arbiter
        },
    );

    let amount: i128 = 1_000;
    let salt = Bytes::from_slice(&env, b"fee_router_dispute_split");
    let commitment = client.deposit(
        &token_id,
        &amount,
        &owner,
        &salt,
        &1000,
        &Some(arbiter.clone()),
        &0u64,
        &u64::MAX,
    );

    client.dispute(&commitment);
    client.resolve_dispute(&arbiter, &commitment, &false, &recipient, &0u64, &u64::MAX);

    // Fee math:
    // total_fee = 100
    // arbiter_fee = 20
    // collector_fee = 80
    // recipient_net = 900
    assert_eq!(token_client.balance(&recipient), 900);
    assert_eq!(token_client.balance(&arbiter), 20);
    assert_eq!(token_client.balance(&collector), 80);

    // Bound safety: payout + arbiter + collector equals gross amount.
    assert_eq!(
        token_client.balance(&recipient)
            + token_client.balance(&arbiter)
            + token_client.balance(&collector),
        amount
    );
    assert_eq!(
        client.get_commitment_state(&commitment),
        Some(EscrowStatus::Spent)
    );
}

#[test]
fn test_fee_router_collector_rotation_applies_to_new_payouts_and_old_escrows() {
    let (env, client, admin) = setup();

    let token_id = create_token(&env);
    let owner = Address::generate(&env);
    let collector_v1 = Address::generate(&env);
    let collector_v2 = Address::generate(&env);

    let token_admin = token::StellarAssetClient::new(&env, &token_id);
    let token_client = token::Client::new(&env, &token_id);

    token_admin.mint(&owner, &20_000);

    client.set_fee_config(&admin, &crate::types::FeeConfig { fee_bps: 1_000 });
    client.set_platform_wallet(&admin, &collector_v1);

    // Escrow created before rotation.
    let amount_old: i128 = 1_000;
    let salt_old = Bytes::from_slice(&env, b"fee_router_old_escrow");
    let old_commitment = client.deposit(
        &token_id,
        &amount_old,
        &owner,
        &salt_old,
        &0,
        &None,
        &0u64,
        &u64::MAX,
    );

    // Rotate collector safely.
    let next_idx = client.rotate_fee_collector(&admin, &collector_v2);
    assert!(next_idx > 0);
    assert_eq!(
        client.get_active_fee_collector(),
        Some(collector_v2.clone())
    );

    // Settling old escrow after rotation should route fee to collector_v2.
    client.withdraw(
        &token_id,
        &amount_old,
        &old_commitment,
        &owner,
        &salt_old,
        &0u64,
        &u64::MAX,
    );

    // New escrow after rotation should also route to collector_v2.
    let amount_new: i128 = 1_000;
    let salt_new = Bytes::from_slice(&env, b"fee_router_new_escrow");
    let new_commitment = client.deposit(
        &token_id,
        &amount_new,
        &owner,
        &salt_new,
        &0,
        &None,
        &1u64,
        &u64::MAX,
    );
    client.withdraw(
        &token_id,
        &amount_new,
        &new_commitment,
        &owner,
        &salt_new,
        &1u64,
        &u64::MAX,
    );

    // 10% fee on each withdrawal => 100 + 100.
    assert_eq!(token_client.balance(&collector_v1), 0);
    assert_eq!(token_client.balance(&collector_v2), 200);

    // Old and new escrows both settled successfully.
    assert_eq!(
        client.get_commitment_state(&old_commitment),
        Some(EscrowStatus::Spent)
    );
    assert_eq!(
        client.get_commitment_state(&new_commitment),
        Some(EscrowStatus::Spent)
    );
}

// ---------------------------------------------------------------------------
// Price-aware fee router tests
// ---------------------------------------------------------------------------

#[test]
fn test_route_payout_price_aware_no_oracle_uses_static_bps() {
    let (env, client, admin) = setup();
    let token = create_token(&env);
    let user = Address::generate(&env);
    let collector = Address::generate(&env);

    let token_admin = token::StellarAssetClient::new(&env, &token);
    let token_client = token::Client::new(&env, &token);

    token_admin.mint(&user, &10_000);

    client.set_fee_config(&admin, &crate::types::FeeConfig { fee_bps: 500 });
    client.set_platform_wallet(&admin, &collector);

    // Perform a deposit+withdraw using price-aware path
    let amount: i128 = 10_000;
    let salt = Bytes::from_slice(&env, b"price_no_oracle");
    let commitment = client.deposit(&token, &amount, &user, &salt, &0, &None, &0u64, &u64::MAX);
    client.withdraw(
        &token, &amount, &commitment, &user, &salt, &0u64, &u64::MAX,
    );

    // No oracle → static 5% → 500 fee
    assert_eq!(token_client.balance(&collector), 500);
    assert_eq!(token_client.balance(&user), 10_000 - 500);
}

#[test]
fn test_route_payout_price_aware_fresh_oracle_uses_dynamic() {
    let (env, client, admin) = setup();
    let token = create_token(&env);
    let user = Address::generate(&env);
    let collector = Address::generate(&env);
    let oracle_addr = Address::generate(&env);

    let token_admin = token::StellarAssetClient::new(&env, &token);
    let token_client = token::Client::new(&env, &token);

    token_admin.mint(&user, &100_000);

    client.set_fee_config(&admin, &crate::types::FeeConfig { fee_bps: 500 });
    client.set_platform_wallet(&admin, &collector);
    client.set_oracle_fee_config(
        &admin,
        &OracleFeeConfig {
            oracle: oracle_addr,
            usd_fee_micros: 500_000,
            stale_threshold_secs: 300,
        },
    );
    client.record_oracle_price(&admin, &10_000_000);

    // Dynamic fee = 50_000
    let amount: i128 = 100_000;
    let salt = Bytes::from_slice(&env, b"price_fresh_oracle");
    let commitment = client.deposit(&token, &amount, &user, &salt, &0, &None, &0u64, &u64::MAX);
    client.withdraw(
        &token, &amount, &commitment, &user, &salt, &0u64, &u64::MAX,
    );

    assert_eq!(token_client.balance(&collector), 50_000);
    assert_eq!(token_client.balance(&user), 100_000 - 50_000);
}

#[test]
fn test_route_payout_price_aware_stale_oracle_rejects() {
    let (env, client, admin) = setup();
    let token = create_token(&env);
    let user = Address::generate(&env);
    let collector = Address::generate(&env);
    let oracle_addr = Address::generate(&env);

    let token_admin = token::StellarAssetClient::new(&env, &token);
    token_admin.mint(&user, &100_000);

    client.set_fee_config(&admin, &crate::types::FeeConfig { fee_bps: 500 });
    client.set_platform_wallet(&admin, &collector);
    client.set_oracle_fee_config(
        &admin,
        &OracleFeeConfig {
            oracle: oracle_addr,
            usd_fee_micros: 500_000,
            stale_threshold_secs: 300,
        },
    );
    client.record_oracle_price(&admin, &10_000_000);

    // Advance past staleness threshold
    env.ledger().with_mut(|li| li.timestamp = 1400);

    // Withdrawal via price-aware path should reject
    let amount: i128 = 100_000;
    let salt = Bytes::from_slice(&env, b"price_stale_reject");
    let commitment = client.deposit(&token, &amount, &user, &salt, &0, &None, &0u64, &u64::MAX);
    let result = client.try_withdraw(
        &token, &amount, &commitment, &user, &salt, &0u64, &u64::MAX,
    );

    match result {
        Err(Ok(err)) => assert_eq!(err, QuickexError::OracleStalePrice),
        _ => panic!("expected OracleStalePrice error, got {:?}", result),
    }
}

#[test]
fn test_route_payout_price_aware_no_oracle_price_rejects() {
    let (env, client, admin) = setup();
    let token = create_token(&env);
    let user = Address::generate(&env);
    let collector = Address::generate(&env);
    let oracle_addr = Address::generate(&env);

    let token_admin = token::StellarAssetClient::new(&env, &token);
    token_admin.mint(&user, &100_000);

    client.set_fee_config(&admin, &crate::types::FeeConfig { fee_bps: 500 });
    client.set_platform_wallet(&admin, &collector);
    client.set_oracle_fee_config(
        &admin,
        &OracleFeeConfig {
            oracle: oracle_addr,
            usd_fee_micros: 500_000,
            stale_threshold_secs: 300,
        },
    );
    // No price cached

    let amount: i128 = 100_000;
    let salt = Bytes::from_slice(&env, b"price_no_cache");
    let commitment = client.deposit(&token, &amount, &user, &salt, &0, &None, &0u64, &u64::MAX);
    let result = client.try_withdraw(
        &token, &amount, &commitment, &user, &salt, &0u64, &u64::MAX,
    );

    match result {
        Err(Ok(err)) => assert_eq!(err, QuickexError::OraclePriceUnavailable),
        _ => panic!("expected OraclePriceUnavailable error, got {:?}", result),
    }
}

#[test]
fn test_route_payout_price_aware_fresh_oracle_dispute_with_arbiter_split() {
    let (env, client, admin) = setup();
    let token = create_token(&env);
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);
    let arbiter = Address::generate(&env);
    let collector = Address::generate(&env);
    let oracle_addr = Address::generate(&env);

    let token_admin = token::StellarAssetClient::new(&env, &token);
    let token_client = token::Client::new(&env, &token);

    token_admin.mint(&owner, &10_000);

    client.set_platform_wallet(&admin, &collector);
    client.set_per_asset_fee(
        &admin,
        &token,
        &PerAssetFeeConfig {
            fee_bps: 1_000,
            arbiter_bps: 2_000,
        },
    );
    // Oracle configured but per-asset overrides it (bypasses oracle)
    client.set_oracle_fee_config(
        &admin,
        &OracleFeeConfig {
            oracle: oracle_addr,
            usd_fee_micros: 500_000,
            stale_threshold_secs: 300,
        },
    );

    let amount: i128 = 1_000;
    let salt = Bytes::from_slice(&env, b"price_aware_dispute");
    let commitment = client.deposit(
        &token,
        &amount,
        &owner,
        &salt,
        &1000,
        &Some(arbiter.clone()),
        &0u64,
        &u64::MAX,
    );

    client.dispute(&commitment);
    client.resolve_dispute(&arbiter, &commitment, &false, &recipient, &0u64, &u64::MAX);

    // Per-asset override: 10% fee, 20% arbiter split
    // total_fee = 100, arbiter = 20, collector = 80
    assert_eq!(token_client.balance(&recipient), 900);
    assert_eq!(token_client.balance(&arbiter), 20);
    assert_eq!(token_client.balance(&collector), 80);
}

#[test]
fn test_route_payout_price_aware_multiple_assets_different_prices() {
    let (env, client, admin) = setup();
    let token_a = create_token(&env);
    let token_b = create_token(&env);
    let user = Address::generate(&env);
    let collector = Address::generate(&env);
    let oracle_addr = Address::generate(&env);

    let token_a_admin = token::StellarAssetClient::new(&env, &token_a);
    let token_b_admin = token::StellarAssetClient::new(&env, &token_b);
    let token_a_client = token::Client::new(&env, &token_a);
    let token_b_client = token::Client::new(&env, &token_b);

    token_a_admin.mint(&user, &200_000);
    token_b_admin.mint(&user, &200_000);

    client.set_fee_config(&admin, &crate::types::FeeConfig { fee_bps: 500 });
    client.set_platform_wallet(&admin, &collector);
    client.set_oracle_fee_config(
        &admin,
        &OracleFeeConfig {
            oracle: oracle_addr,
            usd_fee_micros: 500_000,
            stale_threshold_secs: 300,
        },
    );

    // Token A price = $10 → dynamic fee = 50_000
    client.record_oracle_price(&admin, &10_000_000);

    let amount_a: i128 = 100_000;
    let salt_a = Bytes::from_slice(&env, b"price_asset_a");
    let commit_a = client.deposit(
        &token_a, &amount_a, &user, &salt_a, &0, &None, &0u64, &u64::MAX,
    );
    client.withdraw(
        &token_a, &amount_a, &commit_a, &user, &salt_a, &0u64, &u64::MAX,
    );
    assert_eq!(token_a_client.balance(&collector), 50_000);

    // Token B price = $100 (record new price) → dynamic fee = 5_000
    client.record_oracle_price(&admin, &100_000_000);
    env.ledger().with_mut(|li| li.timestamp = 1100);

    let amount_b: i128 = 100_000;
    let salt_b = Bytes::from_slice(&env, b"price_asset_b");
    let commit_b = client.deposit(
        &token_b, &amount_b, &user, &salt_b, &0, &None, &1u64, &u64::MAX,
    );
    client.withdraw(
        &token_b, &amount_b, &commit_b, &user, &salt_b, &1u64, &u64::MAX,
    );
    assert_eq!(token_b_client.balance(&collector), 5_000);

    // Total collected: 50_000 + 5_000 = 55_000
    assert_eq!(
        token_a_client.balance(&collector) + token_b_client.balance(&collector),
        55_000
    );
    // Bound safety: user got everything else
    assert_eq!(
        token_a_client.balance(&user) + token_b_client.balance(&user),
        200_000 + 200_000 - 55_000
    );
}
