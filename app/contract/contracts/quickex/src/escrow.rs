//! Escrow core logic: deposit, withdraw, and refund.
//!
//! # State Machine
//!
//! ```text
//! [*] --> Pending  : deposit() / deposit_with_commitment()
//! Pending --> Spent    : withdraw(proof)  [current_time < expires_at OR no expiry]
//! Pending --> Refunded : refund(owner)    [current_time >= expires_at]
//! Pending --> Disputed : dispute()        [any participant can call]
//! Disputed --> Spent   : resolve_dispute() [arbiter decides for recipient]
//! Disputed --> Refunded: resolve_dispute() [arbiter decides for owner]
//! ```
//!
//! # Time-lock Invariants
//!
//! These invariants are strictly enforced and must hold at all times:
//!
//! **INV-1 (No early withdrawal):**
//!   If `expires_at > 0` and `env.ledger().timestamp() >= expires_at`,
//!   `withdraw` MUST fail with `EscrowExpired`. There is no override.
//!
//! **INV-2 (No early refund):**
//!   `refund` MUST fail with `EscrowNotExpired` unless BOTH:
//!   - `expires_at > 0` (escrow was created with a timeout), AND
//!   - `env.ledger().timestamp() >= expires_at` (timeout has been reached).
//!
//!  A non-expiring escrow (`expires_at == 0`) can NEVER be refunded via `refund`.
//!
//! **INV-3 (Overflow-safe expiry):**
//!   `expires_at` is always computed via `saturating_add` to prevent u64 overflow.
//!   An `expires_at` of `u64::MAX` is treated as effectively non-expiring for
//!   withdrawal but will never satisfy the `>= expires_at` refund condition in
//!   practice, as the ledger timestamp cannot reach `u64::MAX`.
//!
//! **INV-4 (Disputed funds are locked):**
//!   Neither `withdraw` nor `refund` may succeed while status is `Disputed`.
//!   Only `resolve_dispute` (arbiter-gated) can move funds out of `Disputed`.
//!
//! **INV-5 (Terminal states are final):**
//!   Once status is `Spent` or `Refunded`, no further state transitions are
//!   permitted. All entry points check this before any other logic.
//!
//! ## Asset Type Handling
//!
//! This module supports both Native XLM and Stellar Asset Contract (SAC) tokens:
//! - **Native XLM**: Uses the native lumens asset. The token address will be the stellar
//!   network's native asset identifier.
//! - **SAC Tokens**: Uses wrapped tokens via Stellar Asset Contracts (e.g., USDC, custom tokens).
//!
//! The contract uses the standardized `soroban_sdk::token::Client` which works uniformly across
//! both asset types. No special wrap/unwrap logic is needed as Soroban handles this transparently.
//!
//! Guard rails:
//! - `withdraw` fails with [`EscrowExpired`] if `expires_at > 0` and `now >= expires_at`.
//! - `withdraw` fails with [`AlreadySpent`] if status is not `Pending`.
//! - `withdraw` fails if escrow is `Disputed` (funds locked during dispute).
//! - `refund` fails with [`EscrowNotExpired`] if `expires_at == 0` or `now < expires_at`.
//! - Both fail with [`AlreadySpent`] if status is not `Pending`.
//! - `refund` fails with [`InvalidOwner`] if caller ≠ `entry.owner`.
//! - `dispute` requires an assigned arbiter and `Pending` status.
//! - `resolve_dispute` can only be called by the assigned arbiter.

use soroban_sdk::{token, Address, Bytes, BytesN, Env};

use crate::{
    admin, commitment,
    errors::QuickexError,
    escrow_id, events, fee,
    storage::{
        get_escrow, get_escrow_id_mapping, get_platform_wallet, has_escrow, put_escrow,
        put_escrow_id_mapping, remove_escrow, LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS,
    },
    types::{EscrowEntry, EscrowStatus, Role},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` when an escrow has expired according to the ledger clock.
///
/// Enforces INV-2: an escrow with `expires_at == 0` is considered non-expiring
/// and will NEVER return `true` here, making it ineligible for `refund`.
///
/// Enforces INV-1: once this returns `true`, `withdraw` is permanently blocked.
fn is_expired(env: &Env, entry: &EscrowEntry) -> bool {
    // expires_at == 0 means no timeout was set — never expired
    if entry.expires_at == 0 {
        return false;
    }
    env.ledger().timestamp() >= entry.expires_at
}

/// Returns `true` when an escrow is still within its valid withdrawal window.
///
/// Enforces INV-1: withdrawal is only valid if the escrow has NOT expired.
/// A non-expiring escrow (`expires_at == 0`) is always within its window.
fn is_within_window(env: &Env, entry: &EscrowEntry) -> bool {
    !is_expired(env, entry)
}

/// Validates and computes `expires_at` from `timeout_secs`.
///
/// Enforces INV-3: uses `saturating_add` to prevent u64 overflow. If the
/// result saturates to `u64::MAX`, we reject it explicitly — a timeout so
/// large it overflows is almost certainly a caller error, and allowing
/// `u64::MAX` as `expires_at` would create an escrow that can never be
/// refunded (timestamp can never reach `u64::MAX`) while also permanently
/// blocking withdrawal (INV-1 check: `now >= u64::MAX` is always false for
/// any real ledger). We surface this as `InvalidTimeout` instead of
/// silently creating a broken escrow.
fn compute_expires_at(env: &Env, timeout_secs: u64) -> Result<u64, QuickexError> {
    if timeout_secs == 0 {
        return Ok(0); // non-expiring
    }
    let now = env.ledger().timestamp();
    let expires_at = now.saturating_add(timeout_secs);

    // Guard against saturated overflow: if the result is u64::MAX it means
    // timeout_secs was unreasonably large — reject it explicitly.
    if expires_at == u64::MAX {
        return Err(QuickexError::InvalidTimeout);
    }

    Ok(expires_at)
}

// ---------------------------------------------------------------------------
// deposit
// ---------------------------------------------------------------------------

/// Deposit funds and create an escrow entry keyed by `SHA256(owner || amount || salt)`.
///
/// - Transfers `amount` from `owner` to the contract.
/// - Sets status to `Pending`.
/// - If `timeout_secs > 0`, the escrow expires `timeout_secs` seconds after creation.
///   Pass `0` for a non-expiring escrow.
/// - Optionally sets an `arbiter` who can resolve disputes.
///
/// # Errors
/// - [`InvalidAmount`] – amount ≤ 0.
/// - [`InvalidSalt`] – salt > 1024 bytes.
pub fn deposit(
    env: &Env,
    token: Address,
    amount: i128,
    owner: Address,
    salt: Bytes,
    timeout_secs: u64,
    arbiter: Option<Address>,
) -> Result<BytesN<32>, QuickexError> {
    if amount <= 0 {
        return Err(QuickexError::InvalidAmount);
    }

    owner.require_auth();

    // INV-3: validated, overflow-safe expiry computation
    let expires_at = compute_expires_at(env, timeout_secs)?;

    // Issue #304: deterministic escrow id over the full creation payload.
    // If an identical request has already been recorded, return the
    // existing commitment instead of creating a duplicate escrow.
    let escrow_id =
        escrow_id::derive_escrow_id(env, &token, amount, &owner, &salt, timeout_secs, &arbiter)?;
    if let Some(existing) = get_escrow_id_mapping(env, &escrow_id) {
        return Ok(existing);
    }

    let commitment = commitment::create_amount_commitment(env, owner.clone(), amount, salt)?;
    let now = env.ledger().timestamp();

    // let expires_at = if timeout_secs > 0 {
    //     now.saturating_add(timeout_secs)
    // } else {
    //     0
    // };

    // non-optimized: token.clone() into entry + token used again for client
    // let entry = EscrowEntry {
    //     token: token.clone(),
    //     amount,
    //     owner: owner.clone(),
    //     status: EscrowStatus::Pending,
    //     created_at: now,
    //     expires_at,
    // };
    // put_escrow(env, &commitment.clone().into(), &entry);
    // let token_client = token::Client::new(env, &token);
    // token_client.transfer(&owner, env.current_contract_address(), &amount);
    // events::publish_deposit(env, commitment.clone(), token, amount);

    // optimized: build client first (borrows token), then move token into entry
    // commitment converted to Bytes once, reused
    let token_client = token::Client::new(env, &token);
    let commitment_bytes: Bytes = commitment.clone().into();
    let entry = EscrowEntry {
        token, // moved
        amount,
        owner: owner.clone(),
        status: EscrowStatus::Pending,
        created_at: now,
        expires_at,
        arbiter,
    };

    put_escrow(env, &commitment_bytes, &entry);
    put_escrow_id_mapping(env, &escrow_id, &commitment);
    token_client.transfer(&owner, env.current_contract_address(), &amount);

    events::publish_escrow_deposited(
        env,
        commitment.clone(),
        owner,
        token_client.address,
        amount,
        expires_at,
    );

    Ok(commitment)
}

// ---------------------------------------------------------------------------
// deposit_with_commitment
// ---------------------------------------------------------------------------

/// Deposit using a pre-generated 32-byte commitment hash.
///
/// - Validates commitment uniqueness.
/// - If `timeout_secs > 0`, the escrow expires after that many seconds.
/// - Optionally sets an `arbiter` who can resolve disputes.
///
/// # Errors
/// - [`InvalidAmount`] – amount ≤ 0.
/// - [`CommitmentAlreadyExists`] – commitment already in storage.
/// - [`InvalidTimeout`] – timeout_secs would overflow u64 when added to now.
pub fn deposit_with_commitment(
    env: &Env,
    from: Address,
    token: Address,
    amount: i128,
    commitment: BytesN<32>,
    timeout_secs: u64,
    arbiter: Option<Address>,
) -> Result<(), QuickexError> {
    if amount <= 0 {
        return Err(QuickexError::InvalidAmount);
    }

    from.require_auth();

    // INV-3: validated, overflow-safe expiry computation
    let expires_at = compute_expires_at(env, timeout_secs)?;

    // non-optimized: .clone().into() done twice, from.clone() + token.clone() unnecessarily
    // if has_escrow(env, &commitment.clone().into()) {
    //     return Err(QuickexError::CommitmentAlreadyExists);
    // }
    // let token_client = token::Client::new(env, &token);
    // token_client.transfer(&from, env.current_contract_address(), &amount);
    // let entry = EscrowEntry {
    //     token: token.clone(),
    //     amount,
    //     owner: from.clone(),
    //     status: EscrowStatus::Pending,
    //     created_at: now,
    //     expires_at,
    // };
    // put_escrow(env, &commitment.clone().into(), &entry);
    // events::publish_deposit(env, commitment, token, amount);

    // optimized: convert commitment once, move args into entry
    let commitment_bytes: Bytes = commitment.clone().into();
    if has_escrow(env, &commitment_bytes) {
        return Err(QuickexError::CommitmentAlreadyExists);
    }

    let token_client = token::Client::new(env, &token);
    token_client.transfer(&from, env.current_contract_address(), &amount);

    let now = env.ledger().timestamp();

    let from_ref = from.clone();
    let entry = EscrowEntry {
        token, // moved
        amount,
        owner: from, // moved
        status: EscrowStatus::Pending,
        created_at: now,
        expires_at,
        arbiter,
    };

    put_escrow(env, &commitment_bytes, &entry);
    events::publish_escrow_deposited(
        env,
        commitment,
        from_ref,
        token_client.address,
        amount,
        expires_at,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// withdraw
// ---------------------------------------------------------------------------

/// Withdraw escrowed funds by proving commitment ownership.
///
/// The caller (`to`) must authorize. The commitment is recomputed from
/// `to`, `amount`, and `salt` and must match an existing pending escrow.
///
/// # Time-lock enforcement
/// Enforces INV-1: if `expires_at > 0` and ledger timestamp >= `expires_at`,
/// this function MUST fail. There is no admin override or bypass.
///
/// # Errors
/// - [`InvalidAmount`] – amount ≤ 0.
/// - [`CommitmentNotFound`] – no escrow for computed commitment.
/// - [`EscrowExpired`] – escrow has passed its expiry.
/// - [`AlreadySpent`] – escrow already spent or refunded.
/// - [`InvalidCommitment`] – stored amount ≠ requested amount.
pub fn withdraw(env: &Env, amount: i128, to: Address, salt: Bytes) -> Result<bool, QuickexError> {
    if amount <= 0 {
        return Err(QuickexError::InvalidAmount);
    }

    to.require_auth();

    let commitment = commitment::create_amount_commitment(env, to.clone(), amount, salt)?;
    let commitment_bytes: Bytes = commitment.clone().into();

    let entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;

    // INV-5: terminal states are final
    if entry.status != EscrowStatus::Pending {
        // Distinguish disputed (INV-4) from other terminal states (INV-5)
        if entry.status == EscrowStatus::Disputed {
            return Err(QuickexError::InvalidDisputeState);
        }
        return Err(QuickexError::AlreadySpent);
    }

    // INV-1: strictly enforce the time-lock — no bypass
    if !is_within_window(env, &entry) {
        return Err(QuickexError::EscrowExpired);
    }

    if entry.amount != amount {
        return Err(QuickexError::InvalidCommitment);
    }

    // non-optimized: full EscrowEntry clone
    // let mut updated = entry.clone();
    // updated.status = EscrowStatus::Spent;
    // put_escrow(env, &commitment_bytes, &updated);
    // let token_client = token::Client::new(env, &entry.token);
    // token_client.transfer(&env.current_contract_address(), &to, &amount);
    // events::publish_withdraw_toggled(env, to, commitment);

    // optimized: destructure what we need, move entry instead of cloning
    let token_ref = entry.token.clone();
    let mut updated = entry;
    updated.status = EscrowStatus::Spent;
    put_escrow(env, &commitment_bytes, &updated);

    let fee_amount = fee::calculate_fee(env, amount);
    let payout_amount = amount.saturating_sub(fee_amount);

    let token_client = token::Client::new(env, &token_ref);
    token_client.transfer(&env.current_contract_address(), &to, &payout_amount);

    if fee_amount > 0 {
        if let Some(platform_wallet) = get_platform_wallet(env) {
            token_client.transfer(
                &env.current_contract_address(),
                &platform_wallet,
                &fee_amount,
            );
        }
    }

    events::publish_escrow_withdrawn(env, commitment, to, token_ref, amount, fee_amount);

    Ok(true)
}

// ---------------------------------------------------------------------------
// refund
// ---------------------------------------------------------------------------

/// Refund an expired escrow back to its original owner.
///
/// - Only callable after `expires_at` has been reached (and `expires_at > 0`).
/// - Caller must be the original depositor (`entry.owner`).
/// - Escrow must still be `Pending`.
///
/// # Time-lock enforcement
/// Enforces INV-2: both conditions must hold simultaneously —
/// `expires_at > 0` (was set) AND `now >= expires_at` (has elapsed).
/// A non-expiring escrow (`expires_at == 0`) can never be refunded.
///
/// # Errors
/// - [`CommitmentNotFound`] – no escrow for the given commitment.
/// - [`AlreadySpent`] – escrow already in a terminal state (INV-5).
/// - [`InvalidDisputeState`] – escrow is disputed, funds locked (INV-4).
/// - [`EscrowNotExpired`] – expiry not set or not yet reached (INV-2).
/// - [`InvalidOwner`] – caller is not the original owner.
pub fn refund(env: &Env, commitment: BytesN<32>, caller: Address) -> Result<(), QuickexError> {
    caller.require_auth();

    let commitment_bytes: Bytes = commitment.clone().into();
    let entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;

    // INV-5: terminal states are final
    if entry.status != EscrowStatus::Pending {
        // INV-4: disputed funds are locked — surface a more specific error
        if entry.status == EscrowStatus::Disputed {
            return Err(QuickexError::InvalidDisputeState);
        }
        return Err(QuickexError::AlreadySpent);
    }

    // INV-2: strictly enforce — both expires_at > 0 AND now >= expires_at must hold
    if !is_expired(env, &entry) {
        return Err(QuickexError::EscrowNotExpired);
    }

    if caller != entry.owner {
        return Err(QuickexError::InvalidOwner);
    }

    let mut updated = entry.clone();
    updated.status = EscrowStatus::Refunded;
    put_escrow(env, &commitment_bytes, &updated);

    let token_client = token::Client::new(env, &entry.token);
    token_client.transfer(&env.current_contract_address(), &entry.owner, &entry.amount);

    events::publish_escrow_refunded(env, entry.owner, commitment, entry.token, entry.amount);

    Ok(())
}

// ---------------------------------------------------------------------------
// TTL & Cleanup
// ---------------------------------------------------------------------------

/// Extend the storage TTL of an escrow record.
///
/// Any user can call this to keep an escrow from being archived.
pub fn extend_escrow_ttl(env: &Env, commitment: BytesN<32>) -> Result<(), QuickexError> {
    let commitment_bytes: Bytes = commitment.into();
    if !has_escrow(env, &commitment_bytes) {
        return Err(QuickexError::CommitmentNotFound);
    }

    env.storage().persistent().extend_ttl(
        &crate::storage::DataKey::Escrow(commitment_bytes),
        LEDGER_THRESHOLD,
        SIX_MONTHS_IN_LEDGERS,
    );
    Ok(())
}

/// Cleanup terminal escrow entries to reclaim storage deposits.
///
/// Only escrows in `Spent` or `Refunded` status can be removed.
pub fn cleanup_escrow(env: &Env, commitment: BytesN<32>) -> Result<(), QuickexError> {
    let commitment_bytes: Bytes = commitment.into();
    let entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;

    match entry.status {
        EscrowStatus::Spent | EscrowStatus::Refunded => {
            remove_escrow(env, &commitment_bytes);
            Ok(())
        }
        _ => Err(QuickexError::AlreadySpent), // Reuse error or add a more specific one if needed
    }
}

// ---------------------------------------------------------------------------
// dispute
// ---------------------------------------------------------------------------

/// Initiate a dispute for a pending escrow, locking the funds.
///
/// - Any participant can call this function.
/// - Requires an assigned arbiter.
/// - Escrow must be in `Pending` status.
/// - Changes status to `Disputed`, locking funds until resolution(INV4)
///
/// # Errors
/// - [`CommitmentNotFound`] – no escrow for the given commitment.
/// - [`NoArbiter`] – no arbiter assigned to the escrow.
/// - [`InvalidDisputeState`] – escrow is not in `Pending` status.
pub fn dispute(env: &Env, commitment: BytesN<32>) -> Result<(), QuickexError> {
    let commitment_bytes: Bytes = commitment.clone().into();
    let entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;

    // Guard: must have an arbiter assigned
    let arbiter = entry.arbiter.as_ref().ok_or(QuickexError::NoArbiter)?;

    // Guard: escrow must be in Pending state
    if entry.status != EscrowStatus::Pending {
        return Err(QuickexError::InvalidDisputeState);
    }

    let mut updated = entry.clone();
    updated.status = EscrowStatus::Disputed;
    put_escrow(env, &commitment_bytes, &updated);

    events::publish_escrow_disputed(env, commitment, arbiter.clone());

    Ok(())
}

// ---------------------------------------------------------------------------
// resolve_dispute
// ---------------------------------------------------------------------------

/// Resolve a disputed escrow by determining the recipient of funds.
///
/// - Only callable by the assigned arbiter.
/// - Escrow must be in `Disputed` status (INV4).
/// - Arbiter decides whether funds go to owner (refund) or recipient (spend).
///
/// # Arguments
/// - `commitment`: The escrow commitment hash
/// - `resolve_for_owner`: If `true`, funds go to owner; if `false`, funds go to recipient
/// - `recipient`: Address to receive funds when `resolve_for_owner` is `false`
///
/// # Errors
/// - [`CommitmentNotFound`] – no escrow for the given commitment.
/// - [`NotArbiter`] – caller is not the assigned arbiter.
/// - [`InvalidDisputeState`] – escrow is not in `Disputed` status.
pub fn resolve_dispute(
    env: &Env,
    caller: Address,
    commitment: BytesN<32>,
    resolve_for_owner: bool,
    recipient: Address,
) -> Result<(), QuickexError> {
    let commitment_bytes: Bytes = commitment.clone().into();
    let entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;

    // Guard: caller must be either the assigned arbiter OR have the global Arbiter role.
    caller.require_auth();
    let mut is_authorized = admin::has_role(env, &caller, Role::Arbiter);

    if !is_authorized {
        if let Some(assigned_arbiter) = &entry.arbiter {
            if *assigned_arbiter == caller {
                is_authorized = true;
            }
        }
    }

    if !is_authorized {
        return Err(QuickexError::NotArbiter);
    }

    // Guard: escrow must be in Disputed state
    if entry.status != EscrowStatus::Disputed {
        return Err(QuickexError::InvalidDisputeState);
    }

    let (final_status, recipient_address) = if resolve_for_owner {
        (EscrowStatus::Refunded, entry.owner.clone())
    } else {
        recipient.require_auth();
        (EscrowStatus::Spent, recipient)
    };

    let mut updated = entry.clone();
    updated.status = final_status;
    put_escrow(env, &commitment_bytes, &updated);

    let (payout_amount, fee_amount) = if final_status == EscrowStatus::Spent {
        let fee = fee::calculate_fee(env, entry.amount);
        (entry.amount.saturating_sub(fee), fee)
    } else {
        (entry.amount, 0)
    };

    let token_client = token::Client::new(env, &entry.token);
    token_client.transfer(
        &env.current_contract_address(),
        &recipient_address,
        &payout_amount,
    );

    if fee_amount > 0 {
        if let Some(platform_wallet) = get_platform_wallet(env) {
            token_client.transfer(
                &env.current_contract_address(),
                &platform_wallet,
                &fee_amount,
            );
        }
    }

    if resolve_for_owner {
        events::publish_escrow_refunded(env, entry.owner, commitment, entry.token, entry.amount);
    } else {
        events::publish_escrow_withdrawn(
            env,
            commitment,
            recipient_address,
            entry.token,
            entry.amount,
            fee_amount,
        );
    }

    Ok(())
}
