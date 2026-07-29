use crate::{errors::QuickexError, events, storage, types::CachedOraclePrice};
use soroban_sdk::{Address, Env};

/// Read-only view of the oracle fee configuration.
pub fn get_oracle_fee_config(env: &Env) -> Option<crate::types::OracleFeeConfig> {
    storage::get_oracle_fee_config(env)
}

/// Fetch a cached oracle price and validate it is not stale.
///
/// Returns `Ok((price_micros, recorded_at))` when a fresh price exists, or
/// `Err(QuickexError::OracleStalePrice)` when the cached price exceeds the
/// configured staleness threshold, or `Err(QuickexError::OraclePriceUnavailable)`
/// when no price has been cached yet.
pub fn fetch_price(env: &Env, _oracle: &Address) -> Result<(i128, u64), QuickexError> {
    let cached =
        storage::get_cached_oracle_price(env).ok_or(QuickexError::OraclePriceUnavailable)?;

    if cached.price_micros <= 0 {
        return Err(QuickexError::OraclePriceInvalid);
    }

    let config = storage::get_oracle_fee_config(env).ok_or(QuickexError::OraclePriceUnavailable)?;

    let now = env.ledger().timestamp();
    let age = now.saturating_sub(cached.recorded_at);

    if age > config.stale_threshold_secs {
        return Err(QuickexError::OracleStalePrice);
    }

    Ok((cached.price_micros, cached.recorded_at))
}

/// Record a new oracle price in the contract storage.
///
/// Only callable by the contract itself (admin-gated at the call site).
/// Emits a `OraclePriceUpdated` event with the new price and timestamp.
pub fn record_price(env: &Env, price_micros: i128) -> Result<(), QuickexError> {
    if price_micros <= 0 {
        return Err(QuickexError::OraclePriceInvalid);
    }

    let now = env.ledger().timestamp();
    let record = CachedOraclePrice {
        price_micros,
        recorded_at: now,
    };

    storage::set_cached_oracle_price(env, &record);
    events::publish_oracle_price_updated(env, price_micros, now);

    Ok(())
}

/// Check whether a price record is fresh (not stale) given the current
/// oracle config's threshold.
#[allow(dead_code)]
pub fn is_price_fresh(env: &Env, record: &CachedOraclePrice) -> bool {
    let config = match storage::get_oracle_fee_config(env) {
        Some(c) => c,
        None => return false,
    };

    let now = env.ledger().timestamp();
    let age = now.saturating_sub(record.recorded_at);
    age <= config.stale_threshold_secs && record.price_micros > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{types::OracleFeeConfig, QuickexContract, QuickexContractClient};
    use soroban_sdk::testutils::{Address as _, Ledger};

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

    fn set_oracle_config(
        env: &Env,
        client: &QuickexContractClient<'_>,
        admin: &Address,
        stale_threshold_secs: u64,
    ) {
        let oracle_addr = Address::generate(env);
        client.set_oracle_fee_config(
            admin,
            &OracleFeeConfig {
                oracle: oracle_addr,
                usd_fee_micros: 500_000,
                stale_threshold_secs,
            },
        );
    }

    #[test]
    fn test_fetch_price_unavailable_when_no_cache() {
        let (env, client, admin) = setup();
        set_oracle_config(&env, &client, &admin, 300);

        let oracle_addr = Address::generate(&env);
        let result = env.as_contract(&client.address, || fetch_price(&env, &oracle_addr));
        assert_eq!(result, Err(QuickexError::OraclePriceUnavailable));
    }

    #[test]
    fn test_fetch_price_rejects_stale_data() {
        let (env, client, admin) = setup();
        set_oracle_config(&env, &client, &admin, 300);

        env.as_contract(&client.address, || {
            let result = record_price(&env, 1_000_000);
            assert!(result.is_ok());
        });

        env.ledger().with_mut(|li| li.timestamp = 1400);

        let oracle_addr = Address::generate(&env);
        let result = env.as_contract(&client.address, || fetch_price(&env, &oracle_addr));
        assert_eq!(result, Err(QuickexError::OracleStalePrice));
    }

    #[test]
    fn test_fetch_price_accepts_fresh_data() {
        let (env, client, admin) = setup();
        set_oracle_config(&env, &client, &admin, 300);

        env.as_contract(&client.address, || {
            let result = record_price(&env, 1_000_000);
            assert!(result.is_ok());
        });

        env.ledger().with_mut(|li| li.timestamp = 1200);

        let oracle_addr = Address::generate(&env);
        let result = env.as_contract(&client.address, || fetch_price(&env, &oracle_addr));
        assert_eq!(result, Ok((1_000_000, 1000)));
    }

    #[test]
    fn test_fetch_price_exact_boundary_is_accepted() {
        let (env, client, admin) = setup();
        set_oracle_config(&env, &client, &admin, 300);

        env.as_contract(&client.address, || {
            let result = record_price(&env, 2_000_000);
            assert!(result.is_ok());
        });

        env.ledger().with_mut(|li| li.timestamp = 1300);

        let oracle_addr = Address::generate(&env);
        let result = env.as_contract(&client.address, || fetch_price(&env, &oracle_addr));
        assert_eq!(result, Ok((2_000_000, 1000)));
    }

    #[test]
    fn test_fetch_price_one_past_boundary_is_stale() {
        let (env, client, admin) = setup();
        set_oracle_config(&env, &client, &admin, 300);

        env.as_contract(&client.address, || {
            let result = record_price(&env, 2_000_000);
            assert!(result.is_ok());
        });

        env.ledger().with_mut(|li| li.timestamp = 1301);

        let oracle_addr = Address::generate(&env);
        let result = env.as_contract(&client.address, || fetch_price(&env, &oracle_addr));
        assert_eq!(result, Err(QuickexError::OracleStalePrice));
    }

    #[test]
    fn test_record_price_rejects_zero() {
        let (env, client, _admin) = setup();
        let result = env.as_contract(&client.address, || record_price(&env, 0));
        assert_eq!(result, Err(QuickexError::OraclePriceInvalid));
    }

    #[test]
    fn test_record_price_rejects_negative() {
        let (env, client, _admin) = setup();
        let result = env.as_contract(&client.address, || record_price(&env, -100));
        assert_eq!(result, Err(QuickexError::OraclePriceInvalid));
    }

    #[test]
    fn test_is_price_fresh_returns_true_for_fresh_data() {
        let (env, client, admin) = setup();
        set_oracle_config(&env, &client, &admin, 300);

        env.as_contract(&client.address, || {
            let record = CachedOraclePrice {
                price_micros: 1_000_000,
                recorded_at: 900,
            };
            assert!(is_price_fresh(&env, &record));
        });
    }

    #[test]
    fn test_is_price_fresh_returns_false_for_stale_data() {
        let (env, client, admin) = setup();
        set_oracle_config(&env, &client, &admin, 300);

        env.ledger().with_mut(|li| li.timestamp = 1500);

        env.as_contract(&client.address, || {
            let record = CachedOraclePrice {
                price_micros: 1_000_000,
                recorded_at: 800,
            };
            assert!(!is_price_fresh(&env, &record));
        });
    }

    #[test]
    fn test_is_price_fresh_returns_false_for_zero_price() {
        let (env, client, admin) = setup();
        set_oracle_config(&env, &client, &admin, 300);

        env.as_contract(&client.address, || {
            let record = CachedOraclePrice {
                price_micros: 0,
                recorded_at: 999,
            };
            assert!(!is_price_fresh(&env, &record));
        });
    }
}
