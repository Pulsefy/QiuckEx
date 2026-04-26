//! Batch entry points for gas-efficient multi-escrow operations.
//!
//! Each function processes a `Vec` of inputs and returns a `Vec` of per-item
//! results so callers can distinguish individual failures from successes.
//! Operations are non-atomic: a failure on item N does not roll back items
//! that already succeeded.  A hard cap (`MAX_BATCH_SIZE`) prevents runaway
//! instruction or storage usage.

use soroban_sdk::{contracttype, Address, Env, Vec};

use crate::errors::QuickexError;
use crate::storage::{get_escrow, store_escrow};
use crate::types::{EscrowEntry, EscrowStatus};

/// Maximum number of items allowed in a single batch call.
const MAX_BATCH_SIZE: u32 = 20;

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
    pub recipient: Address,
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
        return Err(QuickexError::InvalidAmount);
    }

    let mut results: Vec<BatchItemResult> = Vec::new(env);

    for (i, item) in items.iter().enumerate() {
        let idx = i as u32;

        if item.amount <= 0 {
            results.push_back(BatchItemResult { index: idx, success: false, error_code: QuickexError::InvalidAmount as u32 });
            continue;
        }

        if get_escrow(env, &item.escrow_id).is_some() {
            results.push_back(BatchItemResult { index: idx, success: false, error_code: QuickexError::EscrowExists as u32 });
            continue;
        }

        let entry = EscrowEntry {
            owner: item.owner.clone(),
            recipient: item.recipient.clone(),
            token: item.token.clone(),
            amount: item.amount,
            status: EscrowStatus::Pending,
            expires_at: item.expires_at,
            arbiter: None,
            commitment: None,
        };

        store_escrow(env, &item.escrow_id, &entry);
        results.push_back(BatchItemResult { index: idx, success: true, error_code: 0 });
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
        return Err(QuickexError::InvalidAmount);
    }

    let now = env.ledger().timestamp();
    let mut results: Vec<BatchItemResult> = Vec::new(env);

    for (i, id) in escrow_ids.iter().enumerate() {
        let idx = i as u32;

        let mut entry = match get_escrow(env, &id) {
            Some(e) => e,
            None => {
                results.push_back(BatchItemResult { index: idx, success: false, error_code: QuickexError::EscrowNotFound as u32 });
                continue;
            }
        };

        if entry.status != EscrowStatus::Pending {
            results.push_back(BatchItemResult { index: idx, success: false, error_code: QuickexError::AlreadySpent as u32 });
            continue;
        }

        if entry.expires_at > 0 && now >= entry.expires_at {
            results.push_back(BatchItemResult { index: idx, success: false, error_code: QuickexError::EscrowExpired as u32 });
            continue;
        }

        entry.status = EscrowStatus::Spent;
        store_escrow(env, &id, &entry);
        results.push_back(BatchItemResult { index: idx, success: true, error_code: 0 });
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
        return Err(QuickexError::InvalidAmount);
    }

    let now = env.ledger().timestamp();
    let mut results: Vec<BatchItemResult> = Vec::new(env);

    for (i, id) in escrow_ids.iter().enumerate() {
        let idx = i as u32;

        let mut entry = match get_escrow(env, &id) {
            Some(e) => e,
            None => {
                results.push_back(BatchItemResult { index: idx, success: false, error_code: QuickexError::EscrowNotFound as u32 });
                continue;
            }
        };

        if entry.status != EscrowStatus::Pending {
            results.push_back(BatchItemResult { index: idx, success: false, error_code: QuickexError::AlreadySpent as u32 });
            continue;
        }

        if entry.expires_at == 0 || now < entry.expires_at {
            results.push_back(BatchItemResult { index: idx, success: false, error_code: QuickexError::EscrowNotExpired as u32 });
            continue;
        }

        entry.status = EscrowStatus::Refunded;
        store_escrow(env, &id, &entry);
        results.push_back(BatchItemResult { index: idx, success: true, error_code: 0 });
    }

    Ok(results)
}
