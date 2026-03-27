//! 플랫폼 fee calculation logic.

use crate::storage;
use soroban_sdk::Env;

/// Calculate the 플랫폼 fee for a given amount.
///
/// Returns the fee amount based on the current `FeeConfig`.
pub fn calculate_fee(env: &Env, amount: i128) -> i128 {
    let config = storage::get_fee_config(env);
    if config.fee_bps == 0 {
        return 0;
    }

    // Fee = amount * bps / 10000
    // We use i128 for calculation to avoid overflow.
    let bps = config.fee_bps as i128;
    (amount * bps) / 10000
}
