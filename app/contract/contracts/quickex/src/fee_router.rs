//! # Fee Router v2 — Issue #305
//!
//! Provides per-asset fee tiers, optional arbiter fee splits, and rotating fee
//! collector addresses without disrupting existing escrows.
//!
//! ## Priority order for fee bps resolution
//!
//! 1. **Per-asset override** — [`DataKey::PerAssetFee(token)`] if configured.
//! 2. **Oracle dynamic** — USD-based fee if oracle is configured and fresh.
//! 3. **Global static** — [`DataKey::FeeConfig`] basis points.
//!
//! ## Arbiter fee split
//!
//! When a per-asset config sets `arbiter_bps > 0` **and** an arbiter address is
//! provided to [`route_payout`], a proportional share of the fee is transferred
//! to the arbiter. The remainder goes to the active collector.
//!
//! Example: `fee_bps = 200`, `arbiter_bps = 2000`, `amount = 10_000`:
//! - Total fee: 200 (2%)
//! - Arbiter portion: 200 × 20% = 40
//! - Collector portion: 200 − 40 = 160
//! - Net to recipient: 9_800
//!
//! ## Collector rotation
//!
//! [`DataKey::FeeCollectorIndex`] holds the current rotation index (u32).
//! [`DataKey::FeeCollector(index)`] stores the Address for each index.
//! Rotating via [`rotate_collector`] bumps the index atomically and stores the
//! new address. Old escrows automatically pay out to the new collector at
//! settlement time — there is no per-escrow frozen collector.
//!
//! Fallback chain: `FeeCollector(index)` → `PlatformWallet` → (no-op if neither set).
//!
//! ## XLM / SAC consistency
//!
//! All transfers use `soroban_sdk::token::Client` which works identically for
//! native XLM and SAC tokens.

use crate::{fee, storage};
use soroban_sdk::{token, Address, Env};

// ---------------------------------------------------------------------------
// Resolution helpers
// ---------------------------------------------------------------------------

/// Resolve the effective fee collector address.
///
/// Reads the current rotation index, then the `FeeCollector` at that index.
/// Falls back to the `PlatformWallet` singleton if no rotated collector has
/// ever been stored.
pub fn active_collector(env: &Env) -> Option<Address> {
    let idx = storage::get_fee_collector_index(env);
    if let Some(addr) = storage::get_fee_collector_at(env, idx) {
        return Some(addr);
    }
    storage::get_platform_wallet(env)
}

/// Resolve arbiter split basis-points for `token`.
///
/// Returns `0` if no per-asset config is set or `arbiter_bps` is explicitly 0.
pub fn resolve_arbiter_bps(env: &Env, token: &Address) -> u32 {
    storage::get_per_asset_fee(env, token)
        .map(|c| c.arbiter_bps)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Collector rotation
// ---------------------------------------------------------------------------

/// Rotate to a new fee collector address.
///
/// Atomically increments the `FeeCollectorIndex` and stores `new_collector`
/// at the new index. All subsequent calls to [`active_collector`] will return
/// `new_collector` until the next rotation.
///
/// **Caller is responsible for authorization** — call only from admin entry points.
pub fn rotate_collector(env: &Env, new_collector: &Address) -> u32 {
    let current = storage::get_fee_collector_index(env);
    let next = current.saturating_add(1);
    storage::set_fee_collector_index(env, next);
    storage::set_fee_collector_at(env, next, new_collector);
    next
}

// ---------------------------------------------------------------------------
// Core routing
// ---------------------------------------------------------------------------

/// Route a settled payout, applying per-asset fees, arbiter splits, and
/// collector rotation in a single atomic operation.
///
/// Performs all token transfers from `env.current_contract_address()`:
/// - Net payout → `recipient`
/// - Arbiter portion of fee → `arbiter` (if `arbiter_bps > 0` and `arbiter` provided)
/// - Platform portion of fee → active collector (if set)
///
/// Returns `(net_payout, total_fee)`.
///
/// # Arguments
/// * `token`     — Token contract address (XLM or SAC)
/// * `recipient` — Beneficiary of the net payout
/// * `amount`    — Gross amount to distribute (must be > 0)
/// * `arbiter`   — Optional arbiter address for fee split
///
/// # Safety
/// If `amount <= 0`, returns `(amount, 0)` without any transfers.
pub fn route_payout(
    env: &Env,
    token: &Address,
    recipient: &Address,
    amount: i128,
    arbiter: Option<&Address>,
) -> (i128, i128) {
    if amount <= 0 {
        return (amount, 0);
    }

    // Resolve total fee using per-asset → oracle → global priority.
    let total_fee = fee::calculate_fee_for_token(env, token, amount);
    let net_payout = amount.saturating_sub(total_fee);

    let token_client = token::Client::new(env, token);
    token_client.transfer(&env.current_contract_address(), recipient, &net_payout);

    if total_fee > 0 {
        let arbiter_bps = resolve_arbiter_bps(env, token);
        let arbiter_fee = if arbiter_bps > 0 && arbiter.is_some() {
            // Arbiter share is a proportion of the total fee.
            (total_fee * arbiter_bps as i128) / 10000
        } else {
            0
        };
        let platform_fee = total_fee.saturating_sub(arbiter_fee);

        if arbiter_fee > 0 {
            if let Some(arb) = arbiter {
                token_client.transfer(&env.current_contract_address(), arb, &arbiter_fee);
            }
        }

        if platform_fee > 0 {
            if let Some(collector) = active_collector(env) {
                token_client.transfer(&env.current_contract_address(), &collector, &platform_fee);
            }
        }
    }

    (net_payout, total_fee)
}
