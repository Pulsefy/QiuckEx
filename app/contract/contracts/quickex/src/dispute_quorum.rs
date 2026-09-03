//! # Dispute Quorum Configuration and Vote Expiry (Issue #865 / SC-W8-04)
//!
//! `vote_for_dispute` / `resolve_dispute_multi_sig` previously drew their
//! quorum requirement straight from the per-escrow `arbiter_threshold` field
//! with no way to tune it after the fact, and votes never went stale — an
//! escrow that could never gather enough live arbiters stayed `Disputed`
//! forever with no path out.
//!
//! This module adds:
//!
//! 1. **Admin-configurable quorum** ([`DisputeQuorumConfig`]) — a single
//!    `quorum` and `vote_ttl_secs` pair, admin-settable within hard
//!    compile-time bounds ([`MIN_QUORUM`]..=[`MAX_QUORUM`],
//!    [`MIN_VOTE_TTL_SECS`]..=[`MAX_VOTE_TTL_SECS`]).
//! 2. **Vote expiry** — a cast vote only counts toward quorum while
//!    `now <= voted_at + vote_ttl_secs`; a stale vote is silently excluded
//!    from the tally (see `storage::count_dispute_votes`).
//! 3. **A frozen per-dispute snapshot** ([`DisputeQuorumSnapshot`]) — the
//!    moment `dispute()` opens a multi-sig dispute, it reads the *current*
//!    [`DisputeQuorumConfig`], clamps `quorum` to `[1, arbiters.len()]`, and
//!    freezes the result (`required_votes`, `vote_ttl_secs`, `deadline =
//!    disputed_at + vote_ttl_secs`) under this dispute's own storage key.
//!    Every later read (`vote_for_dispute`, `resolve_dispute_multi_sig`,
//!    `resolve_dispute_timeout`) uses this frozen snapshot, never the live
//!    config — so an admin changing the global quorum mid-dispute cannot
//!    retroactively tighten or loosen a dispute that is already in flight.
//! 4. **Fallback resolution path** — once `now > deadline` and the fresh
//!    vote count is still below `required_votes`, anyone may call
//!    `escrow::resolve_dispute_timeout`, which deterministically refunds the
//!    owner (the same fail-closed default used elsewhere in this contract,
//!    e.g. the oracle aggregator). This guarantees funds are never
//!    permanently stuck behind a quorum that arbiters failed to reach in time.
//!
//! Voting itself closes at the snapshot's `deadline`
//! ([`QuickexError::InvalidDisputeState`]) so arbiters get immediate
//! feedback instead of casting a vote that silently never counts.

use soroban_sdk::{contracttype, Bytes, Env};

use crate::{
    errors::QuickexError,
    storage::{DataKey, LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS},
};

// ---------------------------------------------------------------------------
// Hard bounds (compile-time constants)
// ---------------------------------------------------------------------------

/// Absolute minimum quorum an admin may configure.
pub const MIN_QUORUM: u32 = 1;

/// Absolute maximum quorum an admin may configure.
pub const MAX_QUORUM: u32 = 15;

/// Default quorum when no config has ever been set.
pub const DEFAULT_QUORUM: u32 = 2;

/// Absolute minimum vote TTL / dispute voting window (~1 hour).
pub const MIN_VOTE_TTL_SECS: u64 = 3_600;

/// Absolute maximum vote TTL / dispute voting window (~30 days).
pub const MAX_VOTE_TTL_SECS: u64 = 30 * 24 * 3_600;

/// Default vote TTL / dispute voting window (~7 days).
pub const DEFAULT_VOTE_TTL_SECS: u64 = 7 * 24 * 3_600;

// ---------------------------------------------------------------------------
// Global, admin-configurable quorum policy
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DisputeQuorumConfig {
    pub quorum: u32,
    pub vote_ttl_secs: u64,
}

impl DisputeQuorumConfig {
    pub fn default_config() -> Self {
        Self {
            quorum: DEFAULT_QUORUM,
            vote_ttl_secs: DEFAULT_VOTE_TTL_SECS,
        }
    }

    /// Validate both fields against the hard compile-time bounds.
    pub fn validate(&self) -> Result<(), QuickexError> {
        if self.quorum < MIN_QUORUM || self.quorum > MAX_QUORUM {
            return Err(QuickexError::QuorumOutOfBounds);
        }
        if self.vote_ttl_secs < MIN_VOTE_TTL_SECS || self.vote_ttl_secs > MAX_VOTE_TTL_SECS {
            return Err(QuickexError::QuorumOutOfBounds);
        }
        Ok(())
    }
}

/// Read the active dispute-quorum policy, falling back to defaults if never configured.
pub fn get_quorum_config(env: &Env) -> DisputeQuorumConfig {
    env.storage()
        .persistent()
        .get(&DataKey::DisputeQuorumConfig)
        .unwrap_or_else(DisputeQuorumConfig::default_config)
}

/// Persist a new dispute-quorum policy (**Admin only**; caller-gating happens
/// at the `lib.rs` entrypoint). Validates bounds before writing.
///
/// Only affects disputes opened *after* this call — see [`DisputeQuorumSnapshot`].
///
/// # Errors
/// - [`QuickexError::QuorumOutOfBounds`] – `quorum` or `vote_ttl_secs` is
///   outside the compile-time hard bounds.
pub fn set_quorum_config(env: &Env, config: DisputeQuorumConfig) -> Result<(), QuickexError> {
    config.validate()?;
    env.storage()
        .persistent()
        .set(&DataKey::DisputeQuorumConfig, &config);
    env.storage().persistent().extend_ttl(
        &DataKey::DisputeQuorumConfig,
        LEDGER_THRESHOLD,
        SIX_MONTHS_IN_LEDGERS,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-dispute frozen snapshot
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DisputeQuorumSnapshot {
    pub required_votes: u32,
    pub vote_ttl_secs: u64,
    pub deadline: u64,
}

fn quorum_key(commitment: &Bytes) -> DataKey {
    DataKey::DisputeQuorum(commitment.clone())
}

/// Compute and persist the frozen quorum snapshot for a dispute that is
/// opening right now. `arbiter_count` must be the number of assigned
/// arbiters (`entry.arbiters.len()`); the configured quorum is clamped to it
/// so a dispute can never require more votes than it has voters.
pub fn open_snapshot(env: &Env, commitment: &Bytes, disputed_at: u64, arbiter_count: u32) {
    let config = get_quorum_config(env);
    let required_votes = config.quorum.clamp(1, arbiter_count.max(1));
    let snapshot = DisputeQuorumSnapshot {
        required_votes,
        vote_ttl_secs: config.vote_ttl_secs,
        deadline: disputed_at.saturating_add(config.vote_ttl_secs),
    };

    let key = quorum_key(commitment);
    env.storage().persistent().set(&key, &snapshot);
    env.storage()
        .persistent()
        .extend_ttl(&key, LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS);
}

/// Read a dispute's frozen quorum snapshot.
///
/// Returns `None` only for a dispute opened before this feature shipped (a
/// pre-upgrade escrow with no snapshot ever written); callers should treat
/// that as "compute one from the current config" via [`open_snapshot`] so
/// old multi-sig disputes remain resolvable after an upgrade.
pub fn get_snapshot(env: &Env, commitment: &Bytes) -> Option<DisputeQuorumSnapshot> {
    let key = quorum_key(commitment);
    let snapshot = env.storage().persistent().get(&key);
    if snapshot.is_some() {
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS);
    }
    snapshot
}
