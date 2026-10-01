//! Batch entry points for gas-efficient multi-escrow operations.
//!
//! Each entry point processes a `Vec` of inputs and returns a `Vec` of
//! per-item results so callers can distinguish individual failures from
//! successes. A hard cap ([`MAX_BATCH_SIZE`]) prevents runaway instruction or
//! storage usage.
//!
//! # Parity with the single-item flows
//!
//! Every item is executed by the *same* function that backs the corresponding
//! single-item entry point — [`crate::escrow::deposit_item`],
//! [`crate::escrow::withdraw_item`], and [`crate::escrow::refund_item`] — so a
//! batch can never diverge from the single-item contract. Each item therefore
//! gets, without exception:
//!
//! - the token `transfer` in the correct direction (owner → contract on create,
//!   contract → recipient on release, contract → owner on refund),
//! - fee routing on release (identical to `withdraw`),
//! - replay protection via its own `nonce` / `valid_until` pair under a
//!   batch-specific [`ActionType`], so a signature minted for a single-item
//!   call can never be replayed against a batch (or the reverse),
//! - the same time-lock and terminal-state invariants,
//! - the same lifecycle event, and
//! - the same `Create` / `Settle` / `Refund` hook invocation.
//!
//! The batch entry points themselves are gated by `pause_policy` exactly like
//! their single-item counterparts (see [`crate::pause_policy::EntryPoint`]), and
//! by the same reentrancy guard.
//!
//! # Escrow identifiers are derived on-chain
//!
//! Callers never supply an escrow id or commitment. Every item carries the same
//! pre-image the single-item flows use (`owner`, `amount`, `salt`,
//! `timeout_secs`, `arbiter`) and the contract derives the commitment and the
//! deterministic escrow id itself. Accepting a caller-supplied key would let a
//! batch name an escrow created by a *different* owner and then pay it out to
//! the wrong address, so the derivation stays on-chain.
//!
//! # Failure semantics
//!
//! Two distinct classes of failure, with different atomicity:
//!
//! 1. **Validation failures** are reported per item as
//!    `BatchItemResult { success: false, error_code }`; the remaining items
//!    still execute. The returned `Vec` is the authoritative outcome.
//! 2. **Traps** — a missing `require_auth` signature or a failing token
//!    `transfer` (e.g. insufficient balance) — abort the whole transaction.
//!    Soroban transactions are atomic, so this reverts every side effect of the
//!    batch, including the transfers already made for earlier items. No partial
//!    state can ever persist.

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, Vec};

use crate::{errors::QuickexError, escrow, escrow::AuthMode, nonce::ActionType};

/// Maximum number of items allowed in a single batch call.
///
/// ## Resource Cost Justification
///
/// Soroban mainnet transaction budget: 400,000,000 CPU instructions (`tx_max_instructions`).
///
/// Per-operation costs (from `bench_core_lifecycle_costs` in bench_test.rs):
/// - `deposit` / `batch_create` item: ~600,000 CPU instructions (native Rust estimate)
/// - `withdraw` / `batch_release` item: ~500,000 CPU instructions
/// - `refund` / `batch_refund` item: ~500,000 CPU instructions
///
/// WASM execution overhead is typically 2-3× native Rust, so worst-case per-op:
/// - `deposit`: ~1,800,000 CPU instructions
/// - `withdraw`/`refund`: ~1,500,000 CPU instructions
///
/// With a 50% safety margin (leaving headroom for auth, storage reads, events):
/// - Available budget: 400,000,000 × 0.50 = 200,000,000 CPU instructions
/// - Max `deposit` batch: 200,000,000 / 1,800,000 ≈ 111 items
/// - Max `withdraw`/`refund` batch: 200,000,000 / 1,500,000 ≈ 133 items
///
/// We choose **20** as a conservative limit that:
/// 1. Stays well within budget even with storage contention or auth overhead
/// 2. Avoids hitting ledger read/write entry limits (max 200 entries per tx)
/// 3. Keeps transaction size small enough for reliable propagation
/// 4. Matches common batch patterns in DeFi protocols (10-25 items)
pub const MAX_BATCH_SIZE: u32 = 20;

/// Per-item outcome returned by every batch function.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchItemResult {
    /// Position of this item in the submitted vector.
    pub index: u32,
    /// Whether the item's escrow transition completed.
    pub success: bool,
    /// Non-zero on failure; maps to `QuickexError` discriminant.
    pub error_code: u32,
    /// The escrow commitment this item resolved to. `Some` whenever the
    /// contract got far enough to derive the commitment — for successful items
    /// and for failures detected after derivation. `None` when the item was
    /// rejected before derivation (e.g. `InvalidAmount`).
    pub commitment: Option<BytesN<32>>,
}

/// Record a successful item.
fn ok(index: u32, commitment: &BytesN<32>) -> BatchItemResult {
    BatchItemResult {
        index,
        success: true,
        error_code: 0,
        commitment: Some(commitment.clone()),
    }
}

/// Record a failed item. `commitment` is `Some` when the item's escrow
/// commitment is known despite the failure — for `batch_refund` it is a
/// caller-supplied input, so it is echoed back for correlation.
fn fail(index: u32, error: QuickexError, commitment: Option<&BytesN<32>>) -> BatchItemResult {
    BatchItemResult {
        index,
        success: false,
        error_code: error as u32,
        commitment: commitment.cloned(),
    }
}

/// Enforce the batch cap before any item is touched, so an oversized batch is
/// rejected without side effects.
fn check_batch_size(len: u32) -> Result<(), QuickexError> {
    if len > MAX_BATCH_SIZE {
        return Err(QuickexError::BatchSizeExceeded);
    }
    Ok(())
}

/// Authorize every address in `addresses` exactly once.
///
/// Soroban records at most one authorization per `(address, contract)` pair per
/// invocation frame and rejects a repeat with `Auth(ExistingValue)`, so a batch
/// that naively re-authorized each item would abort on the second item sharing
/// an owner. Deduplicating here also gets the collection *up front*: if any
/// owner in the batch failed to sign, the transaction is rejected before a
/// single token has moved, rather than part-way through the list.
///
/// Only ever called after [`check_batch_size`], so `addresses` is bounded by
/// [`MAX_BATCH_SIZE`].
fn authorize_distinct(env: &Env, addresses: soroban_sdk::Vec<Address>) {
    let mut seen: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(env);
    for address in addresses.iter() {
        if !seen.contains(address.clone()) {
            seen.push_back(address.clone());
            address.require_auth();
        }
    }
}

// ---------------------------------------------------------------------------
// Batch create
// ---------------------------------------------------------------------------

/// Parameters for a single escrow to be created inside a batch.
///
/// Mirrors the pre-image of [`crate::escrow::deposit`]; the contract derives
/// the commitment and the deterministic escrow id from these fields.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchCreateItem {
    /// Token contract address (native asset address for XLM).
    pub token: Address,
    /// Amount to escrow; must be positive.
    pub amount: i128,
    /// Owner of the funds. Must authorize the token transfer.
    pub owner: Address,
    /// Random salt (0–1024 bytes) for uniqueness.
    pub salt: Bytes,
    /// Seconds from now until the escrow expires (0 = no expiry).
    pub timeout_secs: u64,
    /// Optional single arbiter, exactly as in `deposit`.
    pub arbiter: Option<Address>,
    /// Replay-protection nonce, scoped to `ActionType::BatchCreate`.
    pub nonce: u64,
    /// Replay-protection expiry, scoped to `ActionType::BatchCreate`.
    pub valid_until: u64,
}

/// Create up to [`MAX_BATCH_SIZE`] escrows in one call.
///
/// Each successful item transfers `amount` from the item's `owner` into the
/// contract and records the escrow exactly as [`crate::escrow::deposit`] would.
/// Returns one `BatchItemResult` per input item, in submission order.
///
/// # Errors
/// Only [`QuickexError::BatchSizeExceeded`] is returned from the call itself;
/// every per-item failure is reported in the returned vector.
pub fn batch_create(
    env: &Env,
    items: Vec<BatchCreateItem>,
) -> Result<Vec<BatchItemResult>, QuickexError> {
    check_batch_size(items.len())?;

    let mut owners: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(env);
    for item in items.iter() {
        owners.push_back(item.owner.clone());
    }
    authorize_distinct(env, owners);

    let mut results: soroban_sdk::Vec<BatchItemResult> = soroban_sdk::Vec::new(env);

    for (i, item) in items.iter().enumerate() {
        let idx = i as u32;

        match escrow::deposit_item(
            env,
            item.token.clone(),
            item.amount,
            item.owner.clone(),
            item.salt.clone(),
            item.timeout_secs,
            item.arbiter.clone(),
            item.nonce,
            item.valid_until,
            ActionType::BatchCreate,
            AuthMode::Recorded,
        ) {
            Ok(commitment) => results.push_back(ok(idx, &commitment)),
            Err(e) => results.push_back(fail(idx, e, None)),
        }
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Batch release (withdraw)
// ---------------------------------------------------------------------------

/// Parameters for a single escrow to be released inside a batch.
///
/// Mirrors the pre-image of [`crate::escrow::withdraw`]: the contract recomputes
/// the commitment from `to`, `amount`, and `salt`, so the caller must present
/// the same triple that funded the escrow.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchReleaseItem {
    /// Recipient of the payout. Must authorize, and must be the party that
    /// created the commitment (exactly as in `withdraw`).
    pub to: Address,
    /// Amount held by the escrow; must equal the stored `amount_due`.
    pub amount: i128,
    /// The salt used when the escrow was funded.
    pub salt: Bytes,
    /// Replay-protection nonce, scoped to `ActionType::BatchRelease`.
    pub nonce: u64,
    /// Replay-protection expiry, scoped to `ActionType::BatchRelease`.
    pub valid_until: u64,
}

/// Release up to [`MAX_BATCH_SIZE`] escrows in one call.
///
/// Each successful item marks the escrow `Spent` and pays the recipient through
/// the same fee-aware payout path as [`crate::escrow::withdraw`]. Items that
/// are expired, disputed, already terminal, under-funded, or unknown are
/// reported per item without stopping the rest of the batch.
///
/// # Errors
/// Only [`QuickexError::BatchSizeExceeded`] is returned from the call itself;
/// every per-item failure is reported in the returned vector.
pub fn batch_release(
    env: &Env,
    items: Vec<BatchReleaseItem>,
) -> Result<Vec<BatchItemResult>, QuickexError> {
    check_batch_size(items.len())?;

    let mut recipients: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(env);
    for item in items.iter() {
        recipients.push_back(item.to.clone());
    }
    authorize_distinct(env, recipients);

    let mut results: soroban_sdk::Vec<BatchItemResult> = soroban_sdk::Vec::new(env);

    for (i, item) in items.iter().enumerate() {
        let idx = i as u32;

        match escrow::withdraw_item(
            env,
            item.amount,
            item.to.clone(),
            item.salt.clone(),
            item.nonce,
            item.valid_until,
            ActionType::BatchRelease,
            AuthMode::Recorded,
        ) {
            Ok(commitment) => results.push_back(ok(idx, &commitment)),
            Err(e) => results.push_back(fail(idx, e, None)),
        }
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Batch refund
// ---------------------------------------------------------------------------

/// Parameters for a single escrow to be refunded inside a batch.
///
/// Mirrors the arguments of [`crate::escrow::refund`].
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchRefundItem {
    /// The 32-byte commitment identifying the escrow.
    pub commitment: BytesN<32>,
    /// Replay-protection nonce, scoped to `ActionType::BatchRefund`.
    pub nonce: u64,
    /// Replay-protection expiry, scoped to `ActionType::BatchRefund`.
    pub valid_until: u64,
}

/// Refund up to [`MAX_BATCH_SIZE`] expired escrows in one call.
///
/// `caller` must be the original owner of *every* commitment in the list, and
/// must authorize once. Each item carries its own `nonce` / `valid_until` pair,
/// exactly as a single `refund` would, so a replayed batch fails per item
/// instead of re-refunding. Funds always return to the escrow's recorded
/// `owner` — never to `caller` — so a batch can never redirect a refund. Use
/// [`crate::QuickexContract::finalize_expired_escrow`] for a permissionless
/// multi-owner sweep.
///
/// # Errors
/// Only [`QuickexError::BatchSizeExceeded`] is returned from the call itself;
/// every per-item failure is reported in the returned vector.
pub fn batch_refund(
    env: &Env,
    caller: &Address,
    items: Vec<BatchRefundItem>,
) -> Result<Vec<BatchItemResult>, QuickexError> {
    check_batch_size(items.len())?;

    caller.require_auth();

    let mut results: soroban_sdk::Vec<BatchItemResult> = soroban_sdk::Vec::new(env);

    for (i, item) in items.iter().enumerate() {
        let idx = i as u32;
        let commitment = item.commitment.clone();

        match escrow::refund_item(
            env,
            commitment.clone(),
            caller.clone(),
            item.nonce,
            item.valid_until,
            ActionType::BatchRefund,
            AuthMode::Recorded,
        ) {
            Ok(()) => results.push_back(ok(idx, &commitment)),
            Err(e) => results.push_back(fail(idx, e, Some(&commitment))),
        }
    }

    Ok(results)
}
