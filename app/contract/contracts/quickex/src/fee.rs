//! 플랫폼 fee calculation logic.

use crate::{oracle, storage};
use soroban_sdk::Env;

/// Calculate the 플랫폼 fee for a given amount.
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
            if price_micros > 0 && now.saturating_sub(timestamp) <= oracle_config.stale_threshold_secs {
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
