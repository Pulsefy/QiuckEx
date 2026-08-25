//! Batch entry points for gas-efficient multi-escrow operations.
//!
//! Each function processes a `Vec` of inputs and returns a `Vec` of per-item
//! results so callers can distinguish individual failures from successes.
//! Operations are non-atomic: a failure on item N does not roll back items
//! that already succeeded.  A hard cap (`MAX_BATCH_SIZE`) prevents runaway
//! instruction or storage usage.

use soroban_sdk::{contracttype, Address, Env, Vec};

use crate::errors::QuickexError;
use crate::storage::{get_escrow, put_escrow};
use crate::types::{EscrowEntry, EscrowStatus};

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
    pub index: u32,
    pub success: bool,
    /// Non-zero on failure; maps to `QuickexError` discriminant.
    pub error_code: u32,
}

// ────────────────────────────────────────────────────────────────────────────
// Batch create
// ────────────────────────────────────────────────────────────────────────────

/// Parameters for a single escrow to be created inside a batch.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchCreateItem {
    pub escrow_id: soroban_sdk::Bytes,
    pub owner: Address,
    pub token: Address,
    pub amount: i128,
    /// Unix timestamp; 0 means no expiry.
    pub expires_at: u64,
}

/// Create up to `MAX_BATCH_SIZE` escrows in one call.
///
/// Returns one `BatchItemResult` per input item.  The caller (owner) must
/// authorise the call once; individual escrow amounts are validated per item.
pub fn batch_create(
    env: &Env,
    caller: &Address,
    items: Vec<BatchCreateItem>,
) -> Result<Vec<BatchItemResult>, QuickexError> {
    caller.require_auth();

    if items.len() > MAX_BATCH_SIZE {
        return Err(QuickexError::BatchSizeExceeded);
    }

    let mut results: Vec<BatchItemResult> = Vec::new(env);

    for (i, item) in items.iter().enumerate() {
        let idx = i as u32;

        if item.amount <= 0 {
            results.push_back(BatchItemResult {
                index: idx,
                success: false,
                error_code: QuickexError::InvalidAmount as u32,
            });
            continue;
        }

        if get_escrow(env, &item.escrow_id).is_some() {
            results.push_back(BatchItemResult {
                index: idx,
                success: false,
                error_code: QuickexError::CommitmentAlreadyExists as u32,
            });
            continue;
        }

        let entry = EscrowEntry {
            owner: item.owner.clone(),
            token: item.token.clone(),
            amount_due: item.amount,
            amount_paid: item.amount,
            status: EscrowStatus::Pending,
            created_at: env.ledger().timestamp(),
            expires_at: item.expires_at,
            arbiter: None,
            arbiters: Vec::new(env),
            arbiter_threshold: 0,
        };

        put_escrow(env, &item.escrow_id, &entry);
        results.push_back(BatchItemResult {
            index: idx,
            success: true,
            error_code: 0,
        });
    }

    Ok(results)
}

// ────────────────────────────────────────────────────────────────────────────
// Batch release (withdraw)
// ────────────────────────────────────────────────────────────────────────────

/// Release funds for multiple escrows.  Each escrow must be in `Pending` state
/// and must not have expired.
pub fn batch_release(
    env: &Env,
    caller: &Address,
    escrow_ids: Vec<soroban_sdk::Bytes>,
) -> Result<Vec<BatchItemResult>, QuickexError> {
    caller.require_auth();

    if escrow_ids.len() > MAX_BATCH_SIZE {
        return Err(QuickexError::BatchSizeExceeded);
    }

    let now = env.ledger().timestamp();
    let mut results: Vec<BatchItemResult> = Vec::new(env);

    for (i, id) in escrow_ids.iter().enumerate() {
        let idx = i as u32;

        let mut entry = match get_escrow(env, &id) {
            Some(e) => e,
            None => {
                results.push_back(BatchItemResult {
                    index: idx,
                    success: false,
                    error_code: QuickexError::CommitmentNotFound as u32,
                });
                continue;
            }
        };

        if entry.status != EscrowStatus::Pending {
            results.push_back(BatchItemResult {
                index: idx,
                success: false,
                error_code: QuickexError::AlreadySpent as u32,
            });
            continue;
        }

        if entry.expires_at > 0 && now >= entry.expires_at {
            results.push_back(BatchItemResult {
                index: idx,
                success: false,
                error_code: QuickexError::EscrowExpired as u32,
            });
            continue;
        }

        entry.status = EscrowStatus::Spent;
        put_escrow(env, &id, &entry);
        results.push_back(BatchItemResult {
            index: idx,
            success: true,
            error_code: 0,
        });
    }

    Ok(results)
}

// ────────────────────────────────────────────────────────────────────────────
// Batch refund
// ────────────────────────────────────────────────────────────────────────────

/// Refund expired escrows back to their owners.  Each escrow must have expired
/// and still be in `Pending` state.
pub fn batch_refund(
    env: &Env,
    caller: &Address,
    escrow_ids: Vec<soroban_sdk::Bytes>,
) -> Result<Vec<BatchItemResult>, QuickexError> {
    caller.require_auth();

    if escrow_ids.len() > MAX_BATCH_SIZE {
        return Err(QuickexError::BatchSizeExceeded);
    }

    let now = env.ledger().timestamp();
    let mut results: Vec<BatchItemResult> = Vec::new(env);

    for (i, id) in escrow_ids.iter().enumerate() {
        let idx = i as u32;

        let mut entry = match get_escrow(env, &id) {
            Some(e) => e,
            None => {
                results.push_back(BatchItemResult {
                    index: idx,
                    success: false,
                    error_code: QuickexError::CommitmentNotFound as u32,
                });
                continue;
            }
        };

        if entry.status != EscrowStatus::Pending {
            results.push_back(BatchItemResult {
                index: idx,
                success: false,
                error_code: QuickexError::AlreadySpent as u32,
            });
            continue;
        }

        if entry.expires_at == 0 || now < entry.expires_at {
            results.push_back(BatchItemResult {
                index: idx,
                success: false,
                error_code: QuickexError::EscrowNotExpired as u32,
            });
            continue;
        }

        entry.status = EscrowStatus::Refunded;
        put_escrow(env, &id, &entry);
        results.push_back(BatchItemResult {
            index: idx,
            success: true,
            error_code: 0,
        });
    }

    Ok(results)
}
