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
//! When a per-asset config sets `arbiter_bps > 0` **and** at least one arbiter
//! beneficiary is supplied, a proportional share of the fee is transferred to
//! the arbiters. The remainder goes to the active collector.
//!
//! Example: `fee_bps = 200`, `arbiter_bps = 2000`, `amount = 10_000`:
//! - Total fee: 200 (2%)
//! - Arbiter portion: 200 × 20% = 40
//! - Collector portion: 200 − 40 = 160
//! - Net to recipient: 9_800
//!
//! ### Who the arbiters are
//!
//! The caller of the routing entry point decides, and the two paths differ
//! because their authority models differ:
//!
//! - **Single-arbiter** ([`route_payout_price_aware`]) takes
//!   one `Option<&Address>`: the arbiter who authorized the resolution.
//! - **Multi-arbiter** ([`route_payout_price_aware_split`]) takes a *set* and
//!   divides the arbiter portion equally among them. `resolve_dispute_multi_sig`
//!   uses this: the settlement is permissionless, so the fee is owed to the
//!   set of arbiters whose fresh votes decided the outcome rather than to
//!   whoever happened to submit the resolving transaction (Issue #1005).
//!
//! Equal division is floor-rounded per arbiter and the division remainder is
//! deliberately left with the platform, so `net_payout + arbiter_paid +
//! platform_fee == amount` holds exactly on every path — a small fee spread
//! across many arbiters pays them 0 rather than inventing value.
//!
//! ## Collector rotation
//!
//! [`DataKey::FeeCollectorIndex`] holds the current rotation index (u32).
//! [`DataKey::FeeCollector(index)`] stores the Address for each index.
//! Rotating via [`rotate_collector`] bumps the index atomically and stores the
//! new address. Old escrows automatically pay out to the new collector at
//! settlement time — there is no per-escrow frozen collector.
//!
//! Fallback chain: `FeeCollector(index)` → `PlatformWallet` → accrued fee
//! treasury (Issue #866 / SC-W8-05): if neither is set, the platform portion
//! is credited to a per-token accrued-fee ledger in the contract's own
//! storage instead of being transferred anywhere, and becomes withdrawable
//! via `admin::withdraw_fees` / `QuickexContract::withdraw_fees`.
//!
//! ## XLM / SAC consistency
//!
//! All transfers use `soroban_sdk::token::Client` which works identically for
//! native XLM and SAC tokens.

use crate::{fee, storage};
use soroban_sdk::{token, Address, Env, Vec};

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

/// Pay out `amount` for a settlement whose `total_fee` the caller has already
/// computed, splitting the fee between `arbiters` and the active collector.
///
/// Every routing entry point funnels through here so the conservation
/// invariant — `net_payout + arbiter_paid + platform_fee == amount` — holds
/// identically on the single-arbiter, multi-arbiter, and no-arbiter paths.
///
/// `arbiters` is the beneficiary set: empty means the platform keeps the whole
/// fee, one entry reproduces the single-arbiter split exactly, and N entries
/// divide the arbiter portion equally (see [`route_payout_price_aware_split`]).
///
/// Returns the net payout transferred to `recipient`.
fn distribute_payout(
    env: &Env,
    token_addr: &Address,
    recipient: &Address,
    amount: i128,
    total_fee: i128,
    arbiters: &Vec<Address>,
) -> i128 {
    let token_client = token::Client::new(env, token_addr);
    let net_payout = amount.saturating_sub(total_fee);
    token_client.transfer(&env.current_contract_address(), recipient, &net_payout);

    if total_fee <= 0 {
        return net_payout;
    }

    // The arbiter pool is a proportion of the *total* fee, floor-rounded. With
    // no beneficiaries there is nobody to owe, so the platform keeps it all.
    let arbiter_pool = if arbiters.is_empty() {
        0
    } else {
        fee::fee_from_bps_floor(total_fee, resolve_arbiter_bps(env, token_addr))
    };

    // Equal split, floor-rounded per beneficiary. The division remainder is
    // intentionally not paid out: leaving it with the platform keeps the
    // invariant exact and means a fee too small to divide pays the arbiters 0
    // instead of overpaying them out of the platform's share.
    let beneficiary_count = arbiters.len() as i128;
    let per_arbiter = if arbiter_pool > 0 {
        arbiter_pool / beneficiary_count
    } else {
        0
    };
    let arbiter_paid = per_arbiter.saturating_mul(beneficiary_count);
    let platform_fee = total_fee.saturating_sub(arbiter_paid);

    if per_arbiter > 0 {
        for arbiter in arbiters.iter() {
            token_client.transfer(&env.current_contract_address(), &arbiter, &per_arbiter);
        }
    }

    if platform_fee > 0 {
        if let Some(collector) = active_collector(env) {
            token_client.transfer(&env.current_contract_address(), &collector, &platform_fee);
        } else {
            // No collector configured: retain the platform portion in the
            // contract as a queryable, admin-withdrawable accrued fee
            // balance (Issue #866 / SC-W8-05) instead of leaving it
            // silently unaccounted for in the contract's token balance.
            storage::add_accrued_fee(env, token_addr, platform_fee);
        }
    }

    net_payout
}

/// Normalise the single-arbiter `Option<&Address>` into the beneficiary set
/// [`distribute_payout`] takes, so both shapes share one implementation.
fn single_arbiter_set(env: &Env, arbiter: Option<&Address>) -> Vec<Address> {
    let mut set = Vec::new(env);
    if let Some(addr) = arbiter {
        set.push_back(addr.clone());
    }
    set
}

/// Price-aware payout routing with explicit oracle price validation.
///
/// Uses
/// [`calculate_fee_for_token_price_aware`](crate::fee::calculate_fee_for_token_price_aware)
/// which REJECTS the transaction when an oracle fee config exists but no fresh
/// price is available (rather than silently falling back to static bps).
///
/// # Errors
/// Returns [`QuickexError::OracleStalePrice`] or
/// [`QuickexError::OraclePriceUnavailable`] when oracle is configured but
/// the price is stale or absent.
pub fn route_payout_price_aware(
    env: &Env,
    token: &Address,
    recipient: &Address,
    amount: i128,
    arbiter: Option<&Address>,
) -> Result<(i128, i128), crate::errors::QuickexError> {
    if amount <= 0 {
        return Ok((amount, 0));
    }

    let total_fee = fee::calculate_fee_for_token_price_aware(env, token, amount)?;
    let net_payout = distribute_payout(
        env,
        token,
        recipient,
        amount,
        total_fee,
        &single_arbiter_set(env, arbiter),
    );

    Ok((net_payout, total_fee))
}

/// Price-aware payout routing that divides the arbiter portion of the fee
/// equally across a *set* of arbiters.
///
/// Used by multi-sig dispute resolution (Issue #1005). A single-arbiter
/// resolution is performed by the arbiter themselves, so the fee is plainly
/// owed to `Some(&caller)`. Multi-sig resolution is different: anyone may
/// submit the resolving transaction once quorum is met, so paying the
/// submitting caller would let an arbitrary address collect the arbiter fee.
/// The fee is therefore owed to the arbiters whose fresh votes decided the
/// outcome, and `resolve_dispute_multi_sig` passes exactly that set here.
///
/// An empty `arbiters` degrades to the platform taking the whole fee, exactly
/// like passing `None` to [`route_payout_price_aware`].
///
/// # Arguments
/// * `arbiters` — arbiter fee beneficiaries. Each receives
///   `floor(arbiter_portion / arbiters.len())`; the division remainder stays
///   with the platform. Callers MUST pass a duplicate-free set, or the same
///   address would be paid once per occurrence.
///
/// # Errors
/// Same as [`route_payout_price_aware`].
pub fn route_payout_price_aware_split(
    env: &Env,
    token: &Address,
    recipient: &Address,
    amount: i128,
    arbiters: &Vec<Address>,
) -> Result<(i128, i128), crate::errors::QuickexError> {
    if amount <= 0 {
        return Ok((amount, 0));
    }

    let total_fee = fee::calculate_fee_for_token_price_aware(env, token, amount)?;
    let net_payout = distribute_payout(env, token, recipient, amount, total_fee, arbiters);

    Ok((net_payout, total_fee))
}
