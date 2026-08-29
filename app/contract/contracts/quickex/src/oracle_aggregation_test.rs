//! Integration tests for multi-source oracle median aggregation (SC-W8-06 / Issue #867).
//!
//! Covers the acceptance criteria directly:
//! - Multiple sources registered, with a configurable minimum count.
//! - Reported price is the median of fresh sources.
//! - Sources deviating beyond tolerance are excluded, and exclusion is observable
//!   (via the `OracleSourceExcluded` event).
//! - Falling below the minimum fresh source count fails closed.
//! - Agreement, single outlier, majority stale, and insufficient sources scenarios.

use crate::{
    errors::QuickexError,
    types::{FeeConfig, OracleFeeConfig},
    QuickexContract, QuickexContractClient,
};
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger},
    Address, Env, TryIntoVal,
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

/// Configure the staleness threshold (multi-source aggregation reuses this
/// same `OracleFeeConfig.stale_threshold_secs` for every source).
fn set_stale_threshold(client: &QuickexContractClient<'_>, admin: &Address, secs: u64) {
    let oracle_addr = Address::generate(&client.env);
    client.set_oracle_fee_config(
        admin,
        &OracleFeeConfig {
            oracle: oracle_addr,
            usd_fee_micros: 500_000,
            stale_threshold_secs: secs,
        },
    );
}

fn event_emitted(env: &Env, contract_id: &Address, event_name: &str) -> bool {
    for e in env.events().all().iter() {
        if e.0 != *contract_id {
            continue;
        }
        let topics = e.1;
        if topics.len() < 2 {
            continue;
        }
        let topic1: soroban_sdk::Symbol = topics.get(1).unwrap().try_into_val(env).unwrap();
        if topic1 == soroban_sdk::Symbol::new(env, event_name) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Source registry
// ---------------------------------------------------------------------------

#[test]
fn test_register_and_list_oracle_sources() {
    let (env, client, admin) = setup();
    let s1 = Address::generate(&env);
    let s2 = Address::generate(&env);

    client.register_oracle_source(&admin, &s1);
    client.register_oracle_source(&admin, &s2);

    let sources = client.get_oracle_sources();
    assert_eq!(sources.len(), 2);
    assert!(sources.contains(s1));
    assert!(sources.contains(s2));
}

#[test]
fn test_register_oracle_source_rejects_duplicate() {
    let (env, client, admin) = setup();
    let s1 = Address::generate(&env);

    client.register_oracle_source(&admin, &s1);
    let result = client.try_register_oracle_source(&admin, &s1);
    assert_eq!(result, Err(Ok(QuickexError::OracleSourceAlreadyRegistered)));
}

#[test]
fn test_register_oracle_source_rejects_non_admin() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);
    let source = Address::generate(&env);

    let result = client.try_register_oracle_source(&non_admin, &source);
    assert_eq!(result, Err(Ok(QuickexError::InsufficientRole)));
}

#[test]
fn test_unregister_oracle_source_removes_it() {
    let (env, client, admin) = setup();
    let s1 = Address::generate(&env);
    client.register_oracle_source(&admin, &s1);

    client.unregister_oracle_source(&admin, &s1);

    assert_eq!(client.get_oracle_sources().len(), 0);
}

#[test]
fn test_unregister_oracle_source_rejects_unknown() {
    let (env, client, admin) = setup();
    let unknown = Address::generate(&env);

    let result = client.try_unregister_oracle_source(&admin, &unknown);
    assert_eq!(result, Err(Ok(QuickexError::OracleSourceNotRegistered)));
}

// ---------------------------------------------------------------------------
// Aggregation config
// ---------------------------------------------------------------------------

#[test]
fn test_set_and_get_aggregation_config() {
    let (_env, client, admin) = setup();

    client.set_oracle_aggregation_config(&admin, &3u32, &500u32);
    let config = client.get_oracle_aggregation_config();

    assert_eq!(config.min_sources, 3);
    assert_eq!(config.max_deviation_bps, 500);
}

#[test]
fn test_aggregation_config_defaults_before_configured() {
    let (_env, client, _admin) = setup();

    let config = client.get_oracle_aggregation_config();

    assert_eq!(config.min_sources, 1);
    assert_eq!(config.max_deviation_bps, 10_000);
}

#[test]
fn test_set_aggregation_config_rejects_zero_min_sources() {
    let (_env, client, admin) = setup();

    let result = client.try_set_oracle_aggregation_config(&admin, &0u32, &500u32);
    assert_eq!(result, Err(Ok(QuickexError::InvalidAmount)));
}

#[test]
fn test_set_aggregation_config_rejects_deviation_over_100_percent() {
    let (_env, client, admin) = setup();

    let result = client.try_set_oracle_aggregation_config(&admin, &2u32, &10_001u32);
    assert_eq!(result, Err(Ok(QuickexError::InvalidAmount)));
}

#[test]
fn test_set_aggregation_config_rejects_non_admin() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);

    let result = client.try_set_oracle_aggregation_config(&non_admin, &2u32, &500u32);
    assert_eq!(result, Err(Ok(QuickexError::InsufficientRole)));
}

// ---------------------------------------------------------------------------
// Recording source prices
// ---------------------------------------------------------------------------

#[test]
fn test_record_oracle_source_price_rejects_unregistered_source() {
    let (env, client, _admin) = setup();
    let unregistered = Address::generate(&env);

    let result = client.try_record_oracle_source_price(&unregistered, &1_000_000i128);
    assert_eq!(result, Err(Ok(QuickexError::OracleSourceNotRegistered)));
}

#[test]
fn test_record_oracle_source_price_rejects_non_positive() {
    let (env, client, admin) = setup();
    let source = Address::generate(&env);
    client.register_oracle_source(&admin, &source);

    let zero = client.try_record_oracle_source_price(&source, &0i128);
    assert_eq!(zero, Err(Ok(QuickexError::OraclePriceInvalid)));

    let negative = client.try_record_oracle_source_price(&source, &-5i128);
    assert_eq!(negative, Err(Ok(QuickexError::OraclePriceInvalid)));
}

#[test]
fn test_record_oracle_source_price_emits_event() {
    let (env, client, admin) = setup();
    let source = Address::generate(&env);
    client.register_oracle_source(&admin, &source);

    client.record_oracle_source_price(&source, &1_000_000i128);

    assert!(event_emitted(
        &env,
        &client.address,
        "OracleSourcePriceRecorded"
    ));
}

// ---------------------------------------------------------------------------
// Aggregation scenarios (SC-W8-06 acceptance criteria)
// ---------------------------------------------------------------------------

/// Agreement: three sources report close prices; the median is returned and
/// no source is excluded.
#[test]
fn test_aggregated_price_agreement() {
    let (env, client, admin) = setup();
    set_stale_threshold(&client, &admin, 300);
    client.set_oracle_aggregation_config(&admin, &3u32, &500u32); // 5% tolerance

    let s1 = Address::generate(&env);
    let s2 = Address::generate(&env);
    let s3 = Address::generate(&env);
    client.register_oracle_source(&admin, &s1);
    client.register_oracle_source(&admin, &s2);
    client.register_oracle_source(&admin, &s3);

    client.record_oracle_source_price(&s1, &9_900_000i128);
    client.record_oracle_source_price(&s2, &10_000_000i128);
    client.record_oracle_source_price(&s3, &10_100_000i128);

    let (price, _recorded_at) = client.get_aggregated_oracle_price();
    assert_eq!(price, 10_000_000);
    assert!(!event_emitted(
        &env,
        &client.address,
        "OracleSourceExcluded"
    ));
}

/// Agreement with an even source count exercises the floor-averaged median.
#[test]
fn test_aggregated_price_agreement_even_source_count_floor_averages_median() {
    let (env, client, admin) = setup();
    set_stale_threshold(&client, &admin, 300);
    client.set_oracle_aggregation_config(&admin, &4u32, &500u32);

    let sources = [
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
    ];
    // All four agree within a fraction of a percent, well inside the 5%
    // tolerance, so none are excluded as outliers.
    let prices = [
        9_999_000i128,
        10_000_000i128,
        10_000_002i128,
        10_010_000i128,
    ];
    for (source, price) in sources.iter().zip(prices.iter()) {
        client.register_oracle_source(&admin, source);
        client.record_oracle_source_price(source, price);
    }

    // Middle two sorted prices are 10_000_000 and 10_000_002 -> floor((sum)/2).
    let (price, _) = client.get_aggregated_oracle_price();
    assert_eq!(price, (10_000_000i128 + 10_000_002i128) / 2);
    assert!(!event_emitted(
        &env,
        &client.address,
        "OracleSourceExcluded"
    ));
}

/// Single outlier: one source is wildly off from the other three; it is
/// excluded (observable via `OracleSourceExcluded`) and the median comes
/// from the three that agree.
#[test]
fn test_aggregated_price_single_outlier_excluded() {
    let (env, client, admin) = setup();
    set_stale_threshold(&client, &admin, 300);
    client.set_oracle_aggregation_config(&admin, &3u32, &500u32); // 5% tolerance

    let s1 = Address::generate(&env);
    let s2 = Address::generate(&env);
    let s3 = Address::generate(&env);
    let outlier = Address::generate(&env);
    for s in [&s1, &s2, &s3, &outlier] {
        client.register_oracle_source(&admin, s);
    }

    client.record_oracle_source_price(&s1, &9_950_000i128);
    client.record_oracle_source_price(&s2, &10_000_000i128);
    client.record_oracle_source_price(&s3, &10_050_000i128);
    // Wildly off: 50% above the honest median.
    client.record_oracle_source_price(&outlier, &15_000_000i128);

    let (price, _) = client.get_aggregated_oracle_price();
    assert_eq!(price, 10_000_000, "outlier must not move the final price");
    assert!(event_emitted(&env, &client.address, "OracleSourceExcluded"));
}

/// Majority stale: only one of several registered sources is fresh, which
/// is below the configured minimum, so the price fails closed instead of
/// pricing off the single remaining feed.
#[test]
fn test_aggregated_price_majority_stale_fails_closed() {
    let (env, client, admin) = setup();
    set_stale_threshold(&client, &admin, 300);
    client.set_oracle_aggregation_config(&admin, &3u32, &500u32);

    let s1 = Address::generate(&env);
    let s2 = Address::generate(&env);
    let s3 = Address::generate(&env);
    for s in [&s1, &s2, &s3] {
        client.register_oracle_source(&admin, s);
    }

    // All three record at t=1000.
    client.record_oracle_source_price(&s1, &10_000_000i128);
    client.record_oracle_source_price(&s2, &10_000_000i128);
    client.record_oracle_source_price(&s3, &10_000_000i128);

    // s1 refreshes; s2 and s3 go stale.
    env.ledger().with_mut(|li| li.timestamp = 1301); // > 300s threshold
    client.record_oracle_source_price(&s1, &10_000_000i128);

    let result = client.try_get_aggregated_oracle_price();
    assert_eq!(result, Err(Ok(QuickexError::OracleInsufficientSources)));
}

/// Insufficient sources: fewer sources are ever registered than the
/// configured minimum, so the price fails closed rather than pricing on
/// whatever is available.
#[test]
fn test_aggregated_price_insufficient_sources_fails_closed() {
    let (env, client, admin) = setup();
    set_stale_threshold(&client, &admin, 300);
    client.set_oracle_aggregation_config(&admin, &3u32, &500u32);

    let s1 = Address::generate(&env);
    let s2 = Address::generate(&env);
    client.register_oracle_source(&admin, &s1);
    client.register_oracle_source(&admin, &s2);
    client.record_oracle_source_price(&s1, &10_000_000i128);
    client.record_oracle_source_price(&s2, &10_000_000i128);

    let result = client.try_get_aggregated_oracle_price();
    assert_eq!(result, Err(Ok(QuickexError::OracleInsufficientSources)));
}

/// Outlier exclusion itself can drop the surviving set below the minimum,
/// which must also fail closed rather than silently pricing on fewer feeds.
#[test]
fn test_aggregated_price_fails_closed_when_exclusion_drops_below_minimum() {
    let (env, client, admin) = setup();
    set_stale_threshold(&client, &admin, 300);
    client.set_oracle_aggregation_config(&admin, &3u32, &500u32); // 5% tolerance, need >=3

    let s1 = Address::generate(&env);
    let s2 = Address::generate(&env);
    let outlier = Address::generate(&env);
    for s in [&s1, &s2, &outlier] {
        client.register_oracle_source(&admin, s);
    }

    client.record_oracle_source_price(&s1, &10_000_000i128);
    client.record_oracle_source_price(&s2, &10_000_000i128);
    client.record_oracle_source_price(&outlier, &20_000_000i128);

    // 3 fresh sources clears the initial min_sources gate, but the outlier
    // gets excluded, dropping the kept set to 2 — below the minimum.
    let result = client.try_get_aggregated_oracle_price();
    assert_eq!(result, Err(Ok(QuickexError::OracleInsufficientSources)));
}

#[test]
fn test_aggregated_price_requires_oracle_fee_config_for_staleness_threshold() {
    let (env, client, admin) = setup();
    let source = Address::generate(&env);
    client.register_oracle_source(&admin, &source);
    client.set_oracle_aggregation_config(&admin, &1u32, &500u32);

    // No `set_oracle_fee_config` call, so there is no staleness threshold
    // to evaluate freshness against.
    let result = client.try_record_oracle_source_price(&source, &10_000_000i128);
    assert!(result.is_ok());

    let price_result = client.try_get_aggregated_oracle_price();
    assert_eq!(price_result, Err(Ok(QuickexError::OraclePriceUnavailable)));
}

// ---------------------------------------------------------------------------
// Backward compatibility & end-to-end fee integration
// ---------------------------------------------------------------------------

/// With zero sources registered, fee calculation keeps using the legacy
/// single cached price exactly as before (no behavior change for existing
/// single-oracle deployments).
#[test]
fn test_fee_calculation_falls_back_to_legacy_price_when_no_sources_registered() {
    let (env, client, admin) = setup();
    let token = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    let owner = Address::generate(&env);
    let collector = Address::generate(&env);
    let oracle_addr = Address::generate(&env);

    soroban_sdk::token::StellarAssetClient::new(&env, &token).mint(&owner, &100_000);
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
    client.record_oracle_price(&admin, &10_000_000i128);

    let amount: i128 = 100_000;
    let salt = soroban_sdk::Bytes::from_slice(&env, b"legacy_fallback_salt");
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
    // Legacy dynamic fee = 500_000 * 1_000_000 / 10_000_000 = 50_000 stroops.
    assert_eq!(token_client.balance(&collector), 50_000);
}

/// End-to-end: once sources are registered, the fee router prices off the
/// aggregated median rather than the legacy single price.
#[test]
fn test_fee_calculation_uses_aggregated_median_once_sources_registered() {
    let (env, client, admin) = setup();
    let token = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    let owner = Address::generate(&env);
    let collector = Address::generate(&env);
    let oracle_addr = Address::generate(&env);

    soroban_sdk::token::StellarAssetClient::new(&env, &token).mint(&owner, &100_000);
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
    // Legacy single price says $5/token; if this were still used, the fee
    // would be 100_000 stroops. Sources agree on $10/token instead.
    client.record_oracle_price(&admin, &5_000_000i128);

    let s1 = Address::generate(&env);
    let s2 = Address::generate(&env);
    let s3 = Address::generate(&env);
    for s in [&s1, &s2, &s3] {
        client.register_oracle_source(&admin, s);
    }
    client.set_oracle_aggregation_config(&admin, &3u32, &500u32);
    client.record_oracle_source_price(&s1, &10_000_000i128);
    client.record_oracle_source_price(&s2, &10_000_000i128);
    client.record_oracle_source_price(&s3, &10_000_000i128);

    let amount: i128 = 100_000;
    let salt = soroban_sdk::Bytes::from_slice(&env, b"aggregated_fee_salt");
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
    // Aggregated fee = 500_000 * 1_000_000 / 10_000_000 = 50_000 stroops,
    // not the 100_000 the legacy $5/token price would have produced.
    assert_eq!(token_client.balance(&collector), 50_000);
}
