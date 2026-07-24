//! Platform fee calculation logic with hard bounds and deterministic rounding.

use crate::{errors::QuickexError, oracle, storage};
use soroban_sdk::{Address, Env};

/// Maximum allowable fee in basis points (100% = 10_000 bps).
pub const MAX_FEE_BPS: u32 = 10_000;

/// Denominator for basis-point fee math.
pub const BPS_DENOMINATOR: i128 = 10_000;

/// Reject fee basis points that exceed [`MAX_FEE_BPS`].
pub fn validate_fee_bps(fee_bps: u32) -> Result<(), QuickexError> {
    if fee_bps > MAX_FEE_BPS {
        return Err(QuickexError::InvalidAmount);
    }
    Ok(())
}

/// Compute a bps fee using floor rounding (deterministic, user-favorable).
///
/// Platform fees always use floor so callers never pay more than the configured rate.
pub fn fee_from_bps_floor(amount: i128, bps: u32) -> i128 {
    if amount <= 0 || bps == 0 {
        return 0;
    }
    let bps_i = bps as i128;
    if bps_i >= BPS_DENOMINATOR {
        return amount;
    }
    if let Some(numerator) = amount.checked_mul(bps_i) {
        return numerator / BPS_DENOMINATOR;
    }
    let quotient = amount / BPS_DENOMINATOR;
    let remainder = amount % BPS_DENOMINATOR;
    quotient
        .saturating_mul(bps_i)
        .saturating_add(remainder.saturating_mul(bps_i) / BPS_DENOMINATOR)
}

/// Reserved for paths that must not under-collect when splitting fees; the primary
/// fee path uses [`fee_from_bps_floor`].
#[allow(dead_code)]
pub fn fee_from_bps_ceil(amount: i128, bps: u32) -> i128 {
    if amount <= 0 || bps == 0 {
        return 0;
    }
    let bps_i = bps as i128;
    if bps_i >= BPS_DENOMINATOR {
        return amount;
    }
    if let Some(numerator) = amount.checked_mul(bps_i) {
        return (numerator + BPS_DENOMINATOR - 1) / BPS_DENOMINATOR;
    }
    let floor = fee_from_bps_floor(amount, bps);
    let remainder = amount % BPS_DENOMINATOR;
    if remainder.saturating_mul(bps_i) % BPS_DENOMINATOR == 0 {
        floor
    } else {
        floor.saturating_add(1)
    }
}

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
    fee_from_bps_floor(amount, config.fee_bps)
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
        return fee_from_bps_floor(amount, per_asset.fee_bps);
    }
    // Fall back to oracle + global bps path.
    calculate_fee(env, amount)
}
