use crate::{
    errors::QuickexError,
    events, fee, storage,
    types::{CachedOraclePrice, OracleAggregationConfig},
};
use soroban_sdk::{Address, Env, Vec};

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

// ---------------------------------------------------------------------------
// Multi-source aggregation (SC-W8-06 / Issue #867)
// ---------------------------------------------------------------------------
//
// The single-source `fetch_price`/`record_price` pair above remains
// untouched for backward compatibility: contracts that never register a
// source keep behaving exactly as before. Once at least one source is
// registered, `fetch_effective_price` switches over to the median-based
// aggregation implemented here.

/// Register a trusted oracle source address (**Admin or Operator only** —
/// enforced by the caller in `lib.rs`).
///
/// Each registered source pushes its own price via
/// [`record_source_price`], authorizing with its own key. This bounds the
/// blast radius of a single compromised feed: it can only corrupt its own
/// entry, which the aggregation in [`fetch_aggregated_price`] can then
/// outlier-filter against the other independent sources.
pub fn register_source(env: &Env, source: Address) -> Result<(), QuickexError> {
    let mut sources = storage::get_oracle_sources(env);
    if sources.contains(source.clone()) {
        return Err(QuickexError::OracleSourceAlreadyRegistered);
    }
    sources.push_back(source.clone());
    storage::set_oracle_sources(env, &sources);
    events::publish_oracle_source_registered(env, source);
    Ok(())
}

/// Unregister a previously-registered oracle source.
pub fn unregister_source(env: &Env, source: Address) -> Result<(), QuickexError> {
    let sources = storage::get_oracle_sources(env);
    let mut updated = Vec::new(env);
    let mut found = false;
    for s in sources.iter() {
        if s != source {
            updated.push_back(s);
        } else {
            found = true;
        }
    }
    if !found {
        return Err(QuickexError::OracleSourceNotRegistered);
    }
    storage::set_oracle_sources(env, &updated);
    events::publish_oracle_source_unregistered(env, source);
    Ok(())
}

/// List the currently-registered oracle source addresses.
pub fn get_sources(env: &Env) -> Vec<Address> {
    storage::get_oracle_sources(env)
}

/// Configure the multi-source aggregation policy (**Admin or Operator
/// only** — enforced by the caller in `lib.rs`).
///
/// # Errors
/// * `InvalidAmount` - `min_sources` is 0, or `max_deviation_bps` exceeds 10_000 (100%)
pub fn set_aggregation_config(
    env: &Env,
    min_sources: u32,
    max_deviation_bps: u32,
) -> Result<(), QuickexError> {
    if min_sources == 0 {
        return Err(QuickexError::InvalidAmount);
    }
    if max_deviation_bps > fee::MAX_FEE_BPS {
        return Err(QuickexError::InvalidAmount);
    }
    storage::set_oracle_aggregation_config(
        env,
        &OracleAggregationConfig {
            min_sources,
            max_deviation_bps,
        },
    );
    Ok(())
}

/// Read the current multi-source aggregation policy.
pub fn get_aggregation_config(env: &Env) -> OracleAggregationConfig {
    storage::get_oracle_aggregation_config(env)
}

/// Record a fresh price from a registered oracle source.
///
/// `source` must authorize the call itself and must already be registered
/// via [`register_source`] — unlike the legacy [`record_price`], an
/// Admin/Operator role does **not** substitute for the source's own
/// signature, so compromising the admin key alone cannot forge a source's
/// price.
///
/// # Errors
/// * `OracleSourceNotRegistered` - `source` is not on the registry
/// * `OraclePriceInvalid` - Price is zero or negative
pub fn record_source_price(
    env: &Env,
    source: &Address,
    price_micros: i128,
) -> Result<(), QuickexError> {
    source.require_auth();

    if !storage::get_oracle_sources(env).contains(source.clone()) {
        return Err(QuickexError::OracleSourceNotRegistered);
    }
    if price_micros <= 0 {
        return Err(QuickexError::OraclePriceInvalid);
    }

    let now = env.ledger().timestamp();
    storage::set_oracle_source_price(
        env,
        source,
        &CachedOraclePrice {
            price_micros,
            recorded_at: now,
        },
    );
    events::publish_oracle_source_price_recorded(env, source.clone(), price_micros, now);
    Ok(())
}

/// Insert `item` into `sorted` (ascending by price), keeping it sorted.
///
/// Plain insertion sort: the contract has no `alloc`/`std` sort available,
/// and the number of oracle sources is expected to stay small (single
/// digits to low tens), so O(n²) is negligible here.
fn insert_sorted_by_price(sorted: &mut Vec<(Address, i128, u64)>, item: (Address, i128, u64)) {
    let len = sorted.len();
    let mut idx = 0u32;
    while idx < len {
        let (_, price, _) = sorted.get_unchecked(idx);
        if price >= item.1 {
            break;
        }
        idx += 1;
    }
    sorted.insert(idx, item);
}

/// Median price of an ascending-sorted, non-empty quote list.
///
/// Even-length lists use the floor-average of the two middle prices,
/// matching the codebase's existing floor-rounding convention for
/// deterministic fee math (see [`fee::fee_from_bps_floor`]).
fn median_of_sorted(sorted: &Vec<(Address, i128, u64)>) -> i128 {
    let n = sorted.len();
    if n % 2 == 1 {
        sorted.get_unchecked(n / 2).1
    } else {
        let a = sorted.get_unchecked(n / 2 - 1).1;
        let b = sorted.get_unchecked(n / 2).1;
        a.saturating_add(b) / 2
    }
}

/// Absolute deviation of `price` from `median`, in basis points of `median`.
fn deviation_bps(price: i128, median: i128) -> u32 {
    if median <= 0 {
        // Unreachable in practice: median is derived from prices already
        // validated as positive. Treat defensively as maximal deviation
        // rather than dividing by zero.
        return u32::MAX;
    }
    let diff = (price - median).abs();
    let bps = diff.saturating_mul(fee::BPS_DENOMINATOR) / median;
    if bps > u32::MAX as i128 {
        u32::MAX
    } else {
        bps as u32
    }
}

/// Compute the aggregated multi-source oracle price (SC-W8-06).
///
/// 1. Collects each registered source's cached price, keeping only those
///    that are fresh per the existing staleness guard (positive price,
///    age within `OracleFeeConfig::stale_threshold_secs`).
/// 2. Fails closed with `OracleInsufficientSources` if fewer than
///    `min_sources` are fresh.
/// 3. Computes the median of the fresh set, then excludes any source
///    deviating from it by more than `max_deviation_bps`, publishing an
///    `OracleSourceExcluded` event for each one excluded.
/// 4. Fails closed again if outlier exclusion drops the count below
///    `min_sources`; otherwise returns the median of the surviving set.
///
/// # Errors
/// * `OraclePriceUnavailable` - No oracle fee config is set (needed for the staleness threshold)
/// * `OracleInsufficientSources` - Fewer than `min_sources` fresh, non-outlier sources
pub fn fetch_aggregated_price(env: &Env) -> Result<(i128, u64), QuickexError> {
    let sources = storage::get_oracle_sources(env);
    let agg_config = storage::get_oracle_aggregation_config(env);
    let fee_config =
        storage::get_oracle_fee_config(env).ok_or(QuickexError::OraclePriceUnavailable)?;

    let now = env.ledger().timestamp();

    let mut fresh: Vec<(Address, i128, u64)> = Vec::new(env);
    for source in sources.iter() {
        let record = match storage::get_oracle_source_price(env, &source) {
            Some(r) => r,
            None => continue,
        };
        if record.price_micros <= 0 {
            continue;
        }
        let age = now.saturating_sub(record.recorded_at);
        if age > fee_config.stale_threshold_secs {
            continue;
        }
        insert_sorted_by_price(
            &mut fresh,
            (source, record.price_micros, record.recorded_at),
        );
    }

    if fresh.len() < agg_config.min_sources {
        return Err(QuickexError::OracleInsufficientSources);
    }

    let preliminary_median = median_of_sorted(&fresh);

    let mut kept: Vec<(Address, i128, u64)> = Vec::new(env);
    for i in 0..fresh.len() {
        let (source, price, recorded_at) = fresh.get_unchecked(i);
        let dev_bps = deviation_bps(price, preliminary_median);
        if dev_bps > agg_config.max_deviation_bps {
            events::publish_oracle_source_excluded(
                env,
                source,
                price,
                preliminary_median,
                dev_bps,
                now,
            );
        } else {
            kept.push_back((source, price, recorded_at));
        }
    }

    if kept.len() < agg_config.min_sources {
        return Err(QuickexError::OracleInsufficientSources);
    }

    let final_median = median_of_sorted(&kept);
    let mut latest_recorded_at = 0u64;
    for i in 0..kept.len() {
        let recorded_at = kept.get_unchecked(i).2;
        if recorded_at > latest_recorded_at {
            latest_recorded_at = recorded_at;
        }
    }

    Ok((final_median, latest_recorded_at))
}

/// Resolve the effective oracle price: multi-source aggregation when any
/// sources are registered, otherwise the legacy single cached price.
///
/// This is the function [`crate::fee`] calls, so fee calculation
/// automatically benefits from aggregation once an admin registers sources
/// — no other call site needs to change.
pub fn fetch_effective_price(
    env: &Env,
    legacy_oracle: &Address,
) -> Result<(i128, u64), QuickexError> {
    if storage::get_oracle_sources(env).is_empty() {
        return fetch_price(env, legacy_oracle);
    }
    fetch_aggregated_price(env)
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
