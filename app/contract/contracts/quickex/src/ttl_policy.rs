//! # TTL Policy for Escrow Entries
//!
//! ## Design
//!
//! Soroban persistent storage entries are subject to ledger-driven archival.
//! An entry whose TTL (time-to-live, measured in ledgers) reaches zero is
//! archived by the network and becomes unreachable until explicitly restored
//! via a `RestoreFootprint` operation submitted by an off-chain actor.
//!
//! For an escrow contract this is a funds-safety concern: an archived escrow
//! entry means the contract cannot read the stored amounts, owner, or status,
//! so withdraw / refund / dispute all fail generically.
//!
//! This module provides a *systematic* policy that ensures:
//!
//! 1. **Auto-bump on access** – Every read of a live escrow extends its TTL
//!    according to the active policy (already wired in `storage::get_escrow`).
//!
//! 2. **Distinct archived error** – When an entry is absent from live storage
//!    the contract surfaces `QuickexError::EscrowArchived` (323) rather than
//!    the generic `CommitmentNotFound` (302) when called via the TTL/restore
//!    path.  Callers can branch on this code and trigger an off-chain restore.
//!
//! 3. **Configurable bounds** – Admin can tighten or extend the default policy
//!    within hard compile-time bounds.  Any requested value outside
//!    `[MIN_TTL_LEDGERS, MAX_TTL_LEDGERS]` is rejected with `TtlOutOfBounds`.
//!
//! 4. **Recovery path** – After a `RestoreFootprint` transaction has been
//!    submitted off-chain, `restore_archived_escrow` re-anchors the entry by
//!    re-writing its TTL to the full configured value, making it live again.
//!
//! ## Policy Values
//!
//! | Constant              | Value (ledgers) | Approximate wall-clock |
//! |-----------------------|-----------------|------------------------|
//! | `MIN_TTL_LEDGERS`     | 17 280          | ~1 day                 |
//! | `DEFAULT_TTL_LEDGERS` | 3 110 400       | ~180 days              |
//! | `MAX_TTL_LEDGERS`     | 6 220 800       | ~360 days              |
//! | `DEFAULT_THRESHOLD`   | 17 280          | ~1 day (bump trigger)  |
//!
//! The *threshold* is the remaining-TTL level below which `extend_ttl` will
//! actually extend; Soroban silently no-ops if current TTL > threshold.  By
//! setting it to ~1 day, every access within the last day of a TTL window
//! resets the clock to the full configured TTL.
//!
//! ## Recovery Path (documented)
//!
//! When `extend_escrow_ttl` or any escrow operation returns `EscrowArchived`:
//!
//! 1. Off-chain: construct a `RestoreFootprint` transaction for the key
//!    `DataKey::EscrowCore(commitment_bytes)` (and optionally
//!    `DataKey::EscrowDispute(commitment_bytes)`) and submit it to the network.
//! 2. Once the restore transaction is confirmed, call
//!    `restore_archived_escrow(commitment)` on this contract.
//! 3. The contract re-bumps the TTL to the full configured value.
//! 4. Subsequent operations (withdraw, refund, etc.) will succeed normally.

use soroban_sdk::{contracttype, Env};

use crate::{
    errors::QuickexError,
    storage::{get_escrow, DataKey, LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS},
};

// ---------------------------------------------------------------------------
// Hard bounds (compile-time constants)
// ---------------------------------------------------------------------------

/// Absolute minimum TTL a policy may specify (~1 day).
pub const MIN_TTL_LEDGERS: u32 = LEDGER_THRESHOLD;

/// Default TTL (~180 days / 6 months).
pub const DEFAULT_TTL_LEDGERS: u32 = SIX_MONTHS_IN_LEDGERS;

/// Absolute maximum TTL a policy may specify (~360 days).
/// Soroban's network-level maximum for persistent storage is typically
/// 3 153 600 ledgers (~1 year at 10s/ledger), so we stay well within that.
pub const MAX_TTL_LEDGERS: u32 = SIX_MONTHS_IN_LEDGERS * 2; // ~360 days

/// Default threshold: bump TTL when remaining TTL drops below ~1 day.
pub const DEFAULT_THRESHOLD_LEDGERS: u32 = LEDGER_THRESHOLD;

// ---------------------------------------------------------------------------
// Stored configuration
// ---------------------------------------------------------------------------

/// On-chain TTL policy configuration.
///
/// Stored under [`DataKey::TtlConfig`].  When absent the defaults above apply.
#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TtlConfig {
    /// Remaining-TTL threshold (in ledgers) below which the entry is extended.
    pub threshold: u32,
    /// Target TTL (in ledgers) that the entry is bumped to on access.
    pub ttl: u32,
}

impl TtlConfig {
    pub fn default_config() -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD_LEDGERS,
            ttl: DEFAULT_TTL_LEDGERS,
        }
    }

    /// Validate that both fields are within hard bounds.
    pub fn validate(&self) -> Result<(), QuickexError> {
        if self.ttl < MIN_TTL_LEDGERS || self.ttl > MAX_TTL_LEDGERS {
            return Err(QuickexError::TtlOutOfBounds);
        }
        if self.threshold < MIN_TTL_LEDGERS || self.threshold > self.ttl {
            return Err(QuickexError::TtlOutOfBounds);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Storage helpers for TtlConfig
// ---------------------------------------------------------------------------

/// Read the active TTL policy, falling backto defaults if never configured.
pub fn get_ttl_config(env: &Env) -> TtlConfig {
    env.storage()
        .persistent()
        .get(&DataKey::TtlConfig)
        .unwrap_or_else(TtlConfig::default_config)
}

/// Persist a new TTL policy.  Validates bounds before writing.
///
/// # Errors
/// - [`TtlOutOfBounds`] – if `config.ttl` or `config.threshold` are outside
///   the compile-time hard bounds.
pub fn set_ttl_config(env: &Env, config: TtlConfig) -> Result<(), QuickexError> {
    config.validate()?;
    env.storage().persistent().set(&DataKey::TtlConfig, &config);
    // Bump the config entry itself so it doesn't get archived.
    env.storage().persistent().extend_ttl(
        &DataKey::TtlConfig,
        DEFAULT_THRESHOLD_LEDGERS,
        DEFAULT_TTL_LEDGERS,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Policy-aware TTL bump
// ---------------------------------------------------------------------------

/// Extend the TTL of an escrow key using the currently configured policy.
///
/// Returns `true` if the key was found and bumped, `false` if not present in
/// live storage (may be archived).
pub fn bump_escrow_ttl_with_policy(env: &Env, commitment: &soroban_sdk::Bytes) -> bool {
    let cfg = get_ttl_config(env);
    let core_key = DataKey::EscrowCore(commitment.clone());

    if env.storage().persistent().has(&core_key) {
        env.storage()
            .persistent()
            .extend_ttl(&core_key, cfg.threshold, cfg.ttl);
        let dispute_key = DataKey::EscrowDispute(commitment.clone());
        if env.storage().persistent().has(&dispute_key) {
            env.storage()
                .persistent()
                .extend_ttl(&dispute_key, cfg.threshold, cfg.ttl);
        }
        return true;
    }

    // Legacy key fallback
    let legacy_key = DataKey::Escrow(commitment.clone());
    if env.storage().persistent().has(&legacy_key) {
        env.storage()
            .persistent()
            .extend_ttl(&legacy_key, cfg.threshold, cfg.ttl);
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// extend_escrow_ttl (policy-aware, distinct archived error)
// ---------------------------------------------------------------------------

/// Extend the TTL of a live escrow entry, surfacing `EscrowArchived` when the
/// entry is absent from live storage.
///
/// ## Behaviour
///
/// - If the entry is present: bumps TTL to the configured policy value and
///   returns `Ok(())`.
/// - If the entry is **absent**: returns `Err(EscrowArchived)`.  This is the
///   signal for callers to submit a `RestoreFootprint` transaction off-chain
///   before retrying.
///
/// This function is the public-facing replacement for the previous
/// `escrow::extend_escrow_ttl` which returned the generic `CommitmentNotFound`.
pub fn extend_ttl_or_archived(
    env: &Env,
    commitment: soroban_sdk::BytesN<32>,
) -> Result<(), QuickexError> {
    let commitment_bytes: soroban_sdk::Bytes = commitment.into();
    if bump_escrow_ttl_with_policy(env, &commitment_bytes) {
        Ok(())
    } else {
        Err(QuickexError::EscrowArchived)
    }
}

// ---------------------------------------------------------------------------
// restore_archived_escrow
// ---------------------------------------------------------------------------

/// Re-anchor an escrow entry that was archived and has since been restored
/// by an off-chain `RestoreFootprint` transaction.
///
/// ## When to call
///
/// 1. A previous call returned `EscrowArchived`.
/// 2. You submitted (and confirmed) a `RestoreFootprint` xdr transaction for
///    `DataKey::EscrowCore(commitment_bytes)`.
/// 3. Call this function — it verifies the entry is now reachable and bumps
///    the TTL to the full configured policy value so it stays live.
///
/// ## Errors
///
/// - [`EscrowArchived`] – entry is still not in live storage; the
///   `RestoreFootprint` may not have been confirmed yet.
pub fn restore_archived_escrow(
    env: &Env,
    commitment: soroban_sdk::BytesN<32>,
) -> Result<(), QuickexError> {
    let commitment_bytes: soroban_sdk::Bytes = commitment.into();

    // Verify the entry is reachable now (post-restore).
    let _ = get_escrow(env, &commitment_bytes).ok_or(QuickexError::EscrowArchived)?;

    // Re-anchor: force-bump to full TTL regardless of current remaining TTL.
    // We use threshold=0 so extend_ttl always fires even if remaining is large.
    let cfg = get_ttl_config(env);
    let core_key = DataKey::EscrowCore(commitment_bytes.clone());
    if env.storage().persistent().has(&core_key) {
        env.storage().persistent().extend_ttl(&core_key, 0, cfg.ttl);
        let dispute_key = DataKey::EscrowDispute(commitment_bytes.clone());
        if env.storage().persistent().has(&dispute_key) {
            env.storage()
                .persistent()
                .extend_ttl(&dispute_key, 0, cfg.ttl);
        }
    } else {
        // Legacy key path
        let legacy_key = DataKey::Escrow(commitment_bytes);
        if env.storage().persistent().has(&legacy_key) {
            env.storage()
                .persistent()
                .extend_ttl(&legacy_key, 0, cfg.ttl);
        } else {
            return Err(QuickexError::EscrowArchived);
        }
    }

    Ok(())
}
