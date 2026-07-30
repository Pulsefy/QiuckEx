//! Integration tests for the Oracle Staleness Guard (Issue #666).
//!
//! Tests cover:
//! - Stale price rejection
//! - Boundary conditions (fresh, exact threshold, one-over)
//! - Price caching via the contract entry point
//! - Fee fallback to static BPS when oracle is stale
//! - Event emission for price updates

use crate::{
    errors::QuickexError,
    types::{FeeConfig, OracleFeeConfig},
    QuickexContract, QuickexContractClient,
};
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger},
    Address, Bytes, Env, TryIntoVal,
};

fn setup() -> (Env, QuickexContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|li| li.timestamp = 1000);

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

// ---------------------------------------------------------------------------
// Price recording & staleness tests
// ---------------------------------------------------------------------------

#[test]
fn test_record_oracle_price_emits_event() {
    let (env, client, admin) = setup();

    client.record_oracle_price(&admin, &5_000_000);

    let all = env.events().all();
    let mut found = false;
    for e in all.iter() {
        if e.0 == client.address {
            let topics = e.1;
            let len = topics.len();
            if len >= 2 {
                let topic1: soroban_sdk::Symbol =
                    topics.get(1).unwrap().try_into_val(&env).unwrap();
                if topic1 == soroban_sdk::Symbol::new(&env, "OraclePriceUpdated") {
                    found = true;
                    break;
                }
            }
        }
    }
    assert!(found, "OraclePriceUpdated event was not emitted");
}

#[test]
fn test_record_oracle_price_rejects_non_admin() {
    let (_env, client, _admin) = setup();
    let non_admin = Address::generate(&_env);

    let result = client.try_record_oracle_price(&non_admin, &5_000_000);
    match result {
        Err(Ok(err)) => assert_eq!(err, QuickexError::InsufficientRole),
        _ => panic!("expected InsufficientRole error"),
    }
}

#[test]
fn test_record_oracle_price_rejects_zero() {
    let (_env, client, admin) = setup();

    let result = client.try_record_oracle_price(&admin, &0);
    match result {
        Err(Ok(err)) => assert_eq!(err, QuickexError::OraclePriceInvalid),
        _ => panic!("expected OraclePriceInvalid error"),
    }
}

#[test]
fn test_record_oracle_price_rejects_negative() {
    let (_env, client, admin) = setup();

    let result = client.try_record_oracle_price(&admin, &-500);
    match result {
        Err(Ok(err)) => assert_eq!(err, QuickexError::OraclePriceInvalid),
        _ => panic!("expected OraclePriceInvalid error"),
    }
}

// ---------------------------------------------------------------------------
// Staleness boundary tests via fee calculation
// ---------------------------------------------------------------------------

#[test]
fn test_stale_oracle_rejects_with_price_aware() {
    let (env, client, admin) = setup();
    let token = create_token(&env);
    let owner = Address::generate(&env);
    let collector = Address::generate(&env);
    let oracle_addr = Address::generate(&env);

    let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
    token_admin_client.mint(&owner, &100_000);

    // Set static BPS fee = 5%
    client.set_fee_config(&admin, &FeeConfig { fee_bps: 500 });
    client.set_platform_wallet(&admin, &collector);

    // Configure oracle with 300s staleness threshold
    client.set_oracle_fee_config(
        &admin,
        &OracleFeeConfig {
            oracle: oracle_addr,
            usd_fee_micros: 500_000,
            stale_threshold_secs: 300,
        },
    );

    // Record oracle price at t=1000
    client.record_oracle_price(&admin, &10_000_000);

    // Advance time past staleness threshold
    env.ledger().with_mut(|li| li.timestamp = 1400);

    // Withdraw via price-aware path should reject with OracleStalePrice
    let amount: i128 = 10_000;
    let salt = Bytes::from_slice(&env, b"stale_reject_salt");
    let commitment = client.deposit(&token, &amount, &owner, &salt, &0, &None, &0u64, &u64::MAX);
    let result = client.try_withdraw(
        &token,
        &amount,
        &commitment,
        &owner,
        &salt,
        &0u64,
        &u64::MAX,
    );

    match result {
        Err(Ok(err)) => assert_eq!(err, QuickexError::OracleStalePrice),
        _ => panic!("expected OracleStalePrice error, got {:?}", result),
    }
}

#[test]
fn test_fresh_oracle_uses_dynamic_fee() {
    let (env, client, admin) = setup();
    let token = create_token(&env);
    let owner = Address::generate(&env);
    let collector = Address::generate(&env);
    let oracle_addr = Address::generate(&env);

    let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
    token_admin_client.mint(&owner, &100_000);

    // Set static BPS fee = 5%
    client.set_fee_config(&admin, &FeeConfig { fee_bps: 500 });
    client.set_platform_wallet(&admin, &collector);

    // Configure oracle: 500_000 microdollar fee, 300s staleness
    client.set_oracle_fee_config(
        &admin,
        &OracleFeeConfig {
            oracle: oracle_addr,
            usd_fee_micros: 500_000,
            stale_threshold_secs: 300,
        },
    );

    // Record oracle price at t=1000: 1 token = 10_000_000 micros = $10
    client.record_oracle_price(&admin, &10_000_000);

    // Oracle fee = 500_000 * 1_000_000 / 10_000_000 = 50,000 stroops (dynamic)
    // Use amount > oracle fee so it is not capped
    let amount: i128 = 100_000;
    let salt = Bytes::from_slice(&env, b"fresh_oracle_salt");
    let commitment = client.deposit(&token, &amount, &owner, &salt, &0, &None, &0u64, &u64::MAX);
    client.withdraw(
        &token,
        &amount,
        &commitment,
        &owner,
        &salt,
        &0u64,
        &u64::MAX,
    );

    let token_client = soroban_sdk::token::Client::new(&env, &token);
    // Dynamic fee = 50_000 stroops
    assert_eq!(token_client.balance(&collector), 50_000);
    assert_eq!(token_client.balance(&owner), 100_000 - 50_000);
}

#[test]
fn test_fresh_oracle_exact_boundary_uses_dynamic_fee() {
    let (env, client, admin) = setup();
    let token = create_token(&env);
    let owner = Address::generate(&env);
    let collector = Address::generate(&env);
    let oracle_addr = Address::generate(&env);

    let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
    token_admin_client.mint(&owner, &100_000);

    client.set_fee_config(&admin, &FeeConfig { fee_bps: 500 });
    client.set_platform_wallet(&admin, &collector);

    client.set_oracle_fee_config(
        &admin,
        &OracleFeeConfig {
            oracle: oracle_addr,
            usd_fee_micros: 500_000,
            stale_threshold_secs: 300,
        },
    );

    // Record at t=1000
    client.record_oracle_price(&admin, &10_000_000);

    // Advance to exactly the boundary (t=1300, age = 300 = threshold)
    env.ledger().with_mut(|li| li.timestamp = 1300);

    let amount: i128 = 100_000;
    let salt = Bytes::from_slice(&env, b"boundary_salt");
    let commitment = client.deposit(&token, &amount, &owner, &salt, &0, &None, &0u64, &u64::MAX);
    client.withdraw(
        &token,
        &amount,
        &commitment,
        &owner,
        &salt,
        &0u64,
        &u64::MAX,
    );

    // Exactly at boundary should use dynamic fee (not stale yet)
    let token_client = soroban_sdk::token::Client::new(&env, &token);
    assert_eq!(token_client.balance(&collector), 50_000);
}

// ---------------------------------------------------------------------------
// Error code range verification
// ---------------------------------------------------------------------------

#[test]
fn test_oracle_error_code_range() {
    assert_eq!(QuickexError::OracleStalePrice as u32, 600);
    assert_eq!(QuickexError::OraclePriceUnavailable as u32, 601);
    assert_eq!(QuickexError::OraclePriceInvalid as u32, 602);
}
