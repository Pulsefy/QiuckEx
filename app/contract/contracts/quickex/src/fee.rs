//! 플랫폼 fee calculation logic.

use crate::{oracle, storage};
use soroban_sdk::{Address, Env};

/// Calculate the platform fee for a given amount using the global config.
///
/// Uses dynamic oracle pricing when configured and falls back to the static
/// fee basis points if the oracle is unavailable or stale.
pub fn calculate_fee(env: &Env, amount: i128) -> i128 {
    if amount <= 0 {
        return 0;
    }

    if let Some(oracle_config) = storage::get_oracle_fee_config(env) {
        if let Some((price_micros, timestamp)) = oracle::fetch_price(env, &oracle_config.oracle) {
            let now = env.ledger().timestamp();
            if price_micros > 0
                && now.saturating_sub(timestamp) <= oracle_config.stale_threshold_secs
            {
                let fee = oracle_config
                    .usd_fee_micros
                    .saturating_mul(1_000_000)
                    .checked_div(price_micros)
                    .unwrap_or(0);
                if fee > amount {
                    return amount;
                }
                return fee;
            }
        }
    }

    let config = storage::get_fee_config(env);
    if config.fee_bps == 0 {
        return 0;
    }

    let bps = config.fee_bps as i128;
    (amount * bps) / 10000
}

/// Calculate the platform fee for a specific token (Fee Router v2).
///
/// Priority:
/// 1. Per-asset fee config for `token` (if set).
/// 2. Oracle dynamic pricing (if configured and fresh).
/// 3. Global static `FeeConfig` basis points.
pub fn calculate_fee_for_token(env: &Env, token: &Address, amount: i128) -> i128 {
    if amount <= 0 {
        return 0;
    }
    // Per-asset override is highest priority and bypasses oracle.
    if let Some(per_asset) = storage::get_per_asset_fee(env, token) {
        if per_asset.fee_bps == 0 {
            return 0;
        }
        return (amount * per_asset.fee_bps as i128) / 10000;
    }
    // Fall back to oracle + global bps path.
    calculate_fee(env, amount)
}
