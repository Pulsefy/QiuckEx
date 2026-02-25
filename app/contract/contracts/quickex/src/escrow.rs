//! Escrow core logic: deposit, withdraw, and refund.
//!
//! # State Machine
//!
//! ```text
//! [*] --> Pending  : deposit() / deposit_with_commitment()
//! Pending --> Spent    : withdraw(proof)  [current_time < expires_at OR no expiry]
//! Pending --> Refunded : refund(owner)    [current_time >= expires_at]
//! ```
//!
//! Guard rails:
//! - `withdraw` fails with [`EscrowExpired`] if `expires_at > 0` and `now >= expires_at`.
//! - `refund` fails with [`EscrowNotExpired`] if `expires_at == 0` or `now < expires_at`.
//! - Both fail with [`AlreadySpent`] if status is not `Pending`.
//! - `refund` fails with [`InvalidOwner`] if caller ≠ `entry.owner`.

use soroban_sdk::{token, Address, Bytes, BytesN, Env};

use crate::{
    commitment,
    errors::QuickexError,
    events,
    storage::{get_escrow, has_escrow, put_escrow},
    types::{EscrowEntry, EscrowStatus},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` when an escrow has expired according to the ledger clock.
///
/// An escrow with `expires_at == 0` never expires.
fn is_expired(env: &Env, entry: &EscrowEntry) -> bool {
    entry.expires_at > 0 && env.ledger().timestamp() >= entry.expires_at
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
) -> Result<BytesN<32>, QuickexError> {
    if amount <= 0 {
        return Err(QuickexError::InvalidAmount);
    }

    owner.require_auth();

    let commitment = commitment::create_amount_commitment(env, owner.clone(), amount, salt)?;
    let now = env.ledger().timestamp();
    let expires_at = if timeout_secs > 0 {
        now.saturating_add(timeout_secs)
    } else {
        0
    };

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
    };

    put_escrow(env, &commitment_bytes, &entry);
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
///
/// # Errors
/// - [`InvalidAmount`] – amount ≤ 0.
/// - [`CommitmentAlreadyExists`] – commitment already in storage.
pub fn deposit_with_commitment(
    env: &Env,
    from: Address,
    token: Address,
    amount: i128,
    commitment: BytesN<32>,
    timeout_secs: u64,
) -> Result<(), QuickexError> {
    if amount <= 0 {
        return Err(QuickexError::InvalidAmount);
    }

    from.require_auth();

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
    let expires_at = if timeout_secs > 0 {
        now.saturating_add(timeout_secs)
    } else {
        0
    };

    let from_ref = from.clone();
    let entry = EscrowEntry {
        token, // moved
        amount,
        owner: from, // moved
        status: EscrowStatus::Pending,
        created_at: now,
        expires_at,
    };

    put_escrow(env, &commitment_bytes, &entry);
    events::publish_escrow_deposited(
        env,
        commitment,
        token_client.address,
        from_ref,
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

    if entry.status != EscrowStatus::Pending {
        return Err(QuickexError::AlreadySpent);
    }

    // Guard: block withdrawal if expired.
    if is_expired(env, &entry) {
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

    let token_client = token::Client::new(env, &token_ref);
    token_client.transfer(&env.current_contract_address(), &to, &amount);

    events::publish_escrow_withdrawn(env, commitment, to, token_ref, amount);

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
/// # Errors
/// - [`CommitmentNotFound`] – no escrow for the given commitment.
/// - [`AlreadySpent`] – escrow already in a terminal state.
/// - [`EscrowNotExpired`] – escrow has no timeout or timeout not yet reached.
/// - [`InvalidOwner`] – caller is not the original owner.
pub fn refund(env: &Env, commitment: BytesN<32>, caller: Address) -> Result<(), QuickexError> {
    caller.require_auth();

    let commitment_bytes: Bytes = commitment.clone().into();
    let entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;

    if entry.status != EscrowStatus::Pending {
        return Err(QuickexError::AlreadySpent);
    }

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
