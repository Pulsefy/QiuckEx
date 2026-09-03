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

use soroban_sdk::{token, Address, Bytes, BytesN, Env, Vec};

use crate::{
    admin, commitment, dispute_quorum,
    errors::QuickexError,
    escrow_id, events, fee_router, hook,
    nonce::{self, ActionType},
    storage::{
        count_dispute_votes, get_dispute_vote, get_escrow, get_escrow_id_mapping, has_dispute_vote,
        has_escrow, put_dispute_vote, put_escrow, put_escrow_id_mapping, remove_escrow,
    },
    types::{DisputeVote, EscrowEntry, EscrowStatus, HookEventKind, Role},
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

/// Deposit funds and create an escrow entry keyed by `SHA256(owner || amount_due || salt)`.
///
/// - Transfers `amount` from `owner` to the contract.
/// - Sets `amount_due` to the target amount and `amount_paid` to the initial payment.
/// - Sets status to `Pending`.
/// - If `timeout_secs > 0`, the escrow expires `timeout_secs` seconds after creation.
///   Pass `0` for a non-expiring escrow.
/// - Optionally sets an `arbiter` who can resolve disputes.
///
/// # Errors
/// - [`InvalidAmount`] – amount ≤ 0.
/// - [`InvalidSalt`] – salt > 1024 bytes.
#[allow(clippy::too_many_arguments)]
pub fn deposit(
    env: &Env,
    token: Address,
    amount: i128,
    owner: Address,
    salt: Bytes,
    timeout_secs: u64,
    arbiter: Option<Address>,
    nonce_val: u64,
    valid_until: u64,
) -> Result<BytesN<32>, QuickexError> {
    if amount <= 0 {
        return Err(QuickexError::InvalidAmount);
    }

    owner.require_auth();

    nonce::verify_and_consume(env, &owner, nonce_val, valid_until, ActionType::Deposit)?;

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

    let (commitment, legacy_commitment) =
        commitment::amount_commitment_hashes(env, &owner, amount, &salt)?;
    let now = env.ledger().timestamp();

    // optimized: build client first (borrows token), then move token into entry
    // commitment converted to Bytes once, reused
    let token_client = token::Client::new(env, &token);
    let commitment_bytes: Bytes = commitment.clone().into();
    if has_escrow(env, &commitment_bytes) {
        return Err(QuickexError::CommitmentAlreadyExists);
    }
    if legacy_commitment != commitment {
        let legacy_commitment_bytes: Bytes = legacy_commitment.into();
        if has_escrow(env, &legacy_commitment_bytes) {
            return Err(QuickexError::CommitmentAlreadyExists);
        }
    }
    let entry = EscrowEntry {
        token, // moved
        amount_due: amount,
        amount_paid: amount, // Initial payment is the full amount
        owner: owner.clone(),
        status: EscrowStatus::Pending,
        created_at: now,
        expires_at,
        arbiter,
        arbiters: Vec::new(env),
        arbiter_threshold: 0,
    };

    put_escrow(env, &commitment_bytes, &entry);
    put_escrow_id_mapping(env, &escrow_id, &commitment);
    token_client.transfer(&owner, env.current_contract_address(), &amount);

    let token_address = token_client.address.clone();
    events::publish_escrow_deposited(
        env,
        commitment.clone(),
        owner.clone(),
        token_address.clone(),
        amount,
        amount,
        expires_at,
    );

    hook::invoke_hooks(
        env,
        HookEventKind::Create,
        &commitment,
        owner,
        token_address,
        amount,
        0,
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
#[allow(clippy::too_many_arguments)]
pub fn deposit_with_commitment(
    env: &Env,
    from: Address,
    token: Address,
    amount: i128,
    commitment: BytesN<32>,
    timeout_secs: u64,
    arbiter: Option<Address>,
    nonce_val: u64,
    valid_until: u64,
) -> Result<(), QuickexError> {
    if amount <= 0 {
        return Err(QuickexError::InvalidAmount);
    }

    from.require_auth();

    nonce::verify_and_consume(
        env,
        &from,
        nonce_val,
        valid_until,
        ActionType::DepositWithCommitment,
    )?;

    // INV-3: validated, overflow-safe expiry computation
    let expires_at = compute_expires_at(env, timeout_secs)?;

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
        amount_due: amount,
        amount_paid: amount, // Initial payment is the full amount
        owner: from,         // moved
        status: EscrowStatus::Pending,
        created_at: now,
        expires_at,
        arbiter,
        arbiters: Vec::new(env),
        arbiter_threshold: 0,
    };

    put_escrow(env, &commitment_bytes, &entry);
    let token_addr = token_client.address.clone();
    events::publish_escrow_deposited(
        env,
        commitment.clone(),
        from_ref.clone(),
        token_addr.clone(),
        amount,
        amount,
        expires_at,
    );

    hook::invoke_hooks(
        env,
        HookEventKind::Create,
        &commitment,
        from_ref,
        token_addr,
        amount,
        0,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// deposit_partial
// ---------------------------------------------------------------------------

/// Deposit funds and create an escrow entry with a target amount higher than the initial payment.
///
/// - Transfers `initial_payment` from `owner` to the contract.
/// - Sets `amount_due` to the target amount and `amount_paid` to the initial payment.
/// - Sets status to `Pending`.
/// - If `timeout_secs > 0`, the escrow expires `timeout_secs` seconds after creation.
///   Pass `0` for a non-expiring escrow.
/// - Optionally sets an `arbiter` who can resolve disputes.
///
/// # Errors
/// - [`InvalidAmount`] – initial_payment ≤ 0 or amount_due ≤ 0.
/// - [`Overpayment`] – initial_payment exceeds amount_due.
/// - [`InvalidSalt`] – salt > 1024 bytes.
#[allow(clippy::too_many_arguments)]
pub fn deposit_partial(
    env: &Env,
    token: Address,
    amount_due: i128,
    initial_payment: i128,
    owner: Address,
    salt: Bytes,
    timeout_secs: u64,
    arbiter: Option<Address>,
    nonce_val: u64,
    valid_until: u64,
) -> Result<BytesN<32>, QuickexError> {
    if initial_payment <= 0 {
        return Err(QuickexError::InvalidAmount);
    }
    if amount_due <= 0 {
        return Err(QuickexError::InvalidAmount);
    }
    if initial_payment > amount_due {
        return Err(QuickexError::Overpayment);
    }

    owner.require_auth();

    nonce::verify_and_consume(
        env,
        &owner,
        nonce_val,
        valid_until,
        ActionType::DepositPartial,
    )?;

    // INV-3: validated, overflow-safe expiry computation
    let expires_at = compute_expires_at(env, timeout_secs)?;

    let commitment = commitment::create_amount_commitment(env, owner.clone(), amount_due, salt)?;
    let now = env.ledger().timestamp();

    let token_client = token::Client::new(env, &token);
    let commitment_bytes: Bytes = commitment.clone().into();
    let entry = EscrowEntry {
        token, // moved
        amount_due,
        amount_paid: initial_payment,
        owner: owner.clone(),
        status: EscrowStatus::Pending,
        created_at: now,
        expires_at,
        arbiter,
        arbiters: Vec::new(env),
        arbiter_threshold: 0,
    };

    put_escrow(env, &commitment_bytes, &entry);
    token_client.transfer(&owner, env.current_contract_address(), &initial_payment);

    let token_addr = token_client.address.clone();
    events::publish_escrow_deposited(
        env,
        commitment.clone(),
        owner.clone(),
        token_addr.clone(),
        amount_due,
        initial_payment,
        expires_at,
    );

    hook::invoke_hooks(
        env,
        HookEventKind::Create,
        &commitment,
        owner,
        token_addr,
        initial_payment,
        0,
    );

    Ok(commitment)
}

// ---------------------------------------------------------------------------
// partial_payment
// ---------------------------------------------------------------------------

/// Make a partial payment towards an existing escrow.
///
/// - Transfers `payment_amount` from `payer` to the contract.
/// - Increments `amount_paid` by the payment amount.
/// - Rejects overpayment (payment_amount > remaining amount due).
/// - Emits a `PartialPayment` event.
/// - If payment completes the escrow (amount_paid == amount_due), emits `EscrowFinalized`.
///
/// # Errors
/// - [`InvalidAmount`] – payment_amount ≤ 0.
/// - [`CommitmentNotFound`] – no escrow for the given commitment.
/// - [`AlreadySpent`] – escrow already in a terminal state.
/// - [`EscrowExpired`] – escrow has passed its expiry.
/// - [`Overpayment`] – payment_amount exceeds the remaining amount due.
pub fn partial_payment(
    env: &Env,
    commitment: BytesN<32>,
    payer: Address,
    payment_amount: i128,
    nonce_val: u64,
    valid_until: u64,
) -> Result<(), QuickexError> {
    if payment_amount <= 0 {
        return Err(QuickexError::InvalidAmount);
    }

    payer.require_auth();

    nonce::verify_and_consume(
        env,
        &payer,
        nonce_val,
        valid_until,
        ActionType::PartialPayment,
    )?;

    let commitment_bytes: Bytes = commitment.clone().into();
    let mut entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;

    // INV-5: terminal states are final
    if entry.status != EscrowStatus::Pending {
        return Err(QuickexError::AlreadySpent);
    }

    if is_expired(env, &entry) {
        return Err(QuickexError::EscrowExpired);
    }

    // Calculate remaining amount due
    let remaining = entry.amount_due.saturating_sub(entry.amount_paid);

    // Reject overpayment
    if payment_amount > remaining {
        return Err(QuickexError::Overpayment);
    }

    // Transfer payment to contract
    let token_client = token::Client::new(env, &entry.token);
    token_client.transfer(&payer, env.current_contract_address(), &payment_amount);

    // Update amount_paid
    entry.amount_paid = entry.amount_paid.saturating_add(payment_amount);

    // Check if escrow is now fully paid
    let is_fully_paid = entry.amount_paid >= entry.amount_due;

    put_escrow(env, &commitment_bytes, &entry);

    // Emit partial payment event
    events::publish_partial_payment(
        env,
        commitment.clone(),
        payer.clone(),
        entry.token.clone(),
        payment_amount,
        entry.amount_paid,
        entry.amount_due,
    );

    // If fully paid, emit finalization event
    if is_fully_paid {
        events::publish_escrow_finalized(
            env,
            commitment,
            entry.owner,
            entry.token,
            entry.amount_paid,
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// withdraw – authorization matrix enforced (SC‑W6‑03)
// ---------------------------------------------------------------------------

/// Withdraw escrowed funds by proving commitment ownership.
///
/// The caller (`to`) must authorize. The commitment is recomputed from
/// `to`, `amount_due`, and `salt` and must match an existing pending escrow.
/// The escrow must be fully paid (amount_paid >= amount_due).
///
/// # Time-lock enforcement
/// Enforces INV-1: if `expires_at > 0` and ledger timestamp >= `expires_at`,
/// this function MUST fail. There is no admin override or bypass.
///
/// # Errors
/// - [`InvalidAmount`] – amount_due ≤ 0.
/// - [`CommitmentNotFound`] – no escrow for computed commitment.
/// - [`EscrowExpired`] – escrow has passed its expiry.
/// - [`AlreadySpent`] – escrow already spent or refunded.
/// - [`InvalidCommitment`] – stored amount_due ≠ requested amount_due.
/// - [`Overpayment`] – escrow is not fully paid yet.
pub fn withdraw(
    env: &Env,
    amount: i128,
    to: Address,
    salt: Bytes,
    nonce_val: u64,
    valid_until: u64,
) -> Result<bool, QuickexError> {
    if amount <= 0 {
        return Err(QuickexError::InvalidAmount);
    }

    to.require_auth();

    nonce::verify_and_consume(env, &to, nonce_val, valid_until, ActionType::Withdraw)?;

    let (commitment, legacy_commitment) =
        commitment::amount_commitment_hashes(env, &to, amount, &salt)?;
    let commitment_bytes: Bytes = commitment.clone().into();

    let (commitment, commitment_bytes, entry): (BytesN<32>, Bytes, EscrowEntry) =
        if let Some(entry) = get_escrow(env, &commitment_bytes) {
            (commitment, commitment_bytes, entry)
        } else {
            let legacy_commitment_bytes: Bytes = legacy_commitment.clone().into();
            let entry = get_escrow(env, &legacy_commitment_bytes)
                .ok_or(QuickexError::CommitmentNotFound)?;
            (legacy_commitment, legacy_commitment_bytes, entry)
        };

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

    if entry.amount_due != amount {
        return Err(QuickexError::InvalidCommitment);
    }

    // Check if escrow is fully paid
    if entry.amount_paid < entry.amount_due {
        return Err(QuickexError::Overpayment);
    }

    // optimized: destructure what we need, move entry instead of cloning
    let token_ref = entry.token.clone();
    let amount_paid = entry.amount_paid;
    let owner = entry.owner.clone();

    let mut updated = entry;
    updated.status = EscrowStatus::Spent;
    put_escrow(env, &commitment_bytes, &updated);

    let (_payout_amount, fee_amount) =
        fee_router::route_payout_price_aware(env, &token_ref, &to, amount_paid, None)?;

    events::publish_escrow_withdrawn(
        env,
        commitment.clone(),
        to.clone(),
        token_ref.clone(),
        amount_paid,
        fee_amount,
    );

    hook::invoke_hooks(
        env,
        HookEventKind::Settle,
        &commitment,
        owner,
        token_ref,
        amount_paid,
        fee_amount,
    );

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
pub fn refund(
    env: &Env,
    commitment: BytesN<32>,
    caller: Address,
    nonce_val: u64,
    valid_until: u64,
) -> Result<(), QuickexError> {
    caller.require_auth();

    nonce::verify_and_consume(env, &caller, nonce_val, valid_until, ActionType::Refund)?;

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

    let token_ref = entry.token.clone();
    let owner_ref = entry.owner.clone();
    let amount_paid = entry.amount_paid;

    let mut updated = entry;
    updated.status = EscrowStatus::Refunded;
    put_escrow(env, &commitment_bytes, &updated);

    let token_client = token::Client::new(env, &token_ref);
    token_client.transfer(&env.current_contract_address(), &owner_ref, &amount_paid);

    events::publish_escrow_refunded(
        env,
        owner_ref.clone(),
        commitment.clone(),
        token_ref.clone(),
        amount_paid,
    );

    hook::invoke_hooks(
        env,
        HookEventKind::Refund,
        &commitment,
        owner_ref,
        token_ref,
        amount_paid,
        0,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// finalize_expired_escrow — SC-W6-04: deterministic, permissionless finalization
// ---------------------------------------------------------------------------

/// Finalize a refund for an expired escrow, callable by **anyone** — no owner
/// signature required.
///
/// This is the deterministic counterpart to [`refund`]: `refund` requires the
/// owner to authorize and submit the transaction themselves. `finalize_expired_escrow`
/// removes that requirement entirely so that an expired escrow can be swept by
/// any caller (e.g. a keeper, cron job, or another participant) once the
/// timeout has passed, with funds always going to `entry.owner` regardless of
/// who calls. This lets expired flows resolve cleanly on testnet without
/// manual intervention from the original depositor.
///
/// Shares the same eligibility rule as `refund` (INV-2): both
/// `expires_at > 0` and `now >= expires_at` must hold. See [`is_expired`].
///
/// # Errors
/// - [`CommitmentNotFound`] – no escrow for the given commitment.
/// - [`AlreadySpent`] – escrow already in a terminal state (INV-5), including
///   an escrow that has already been refunded — this call is not repeatable.
/// - [`InvalidDisputeState`] – escrow is disputed, funds locked (INV-4).
/// - [`EscrowNotExpired`] – expiry not set or not yet reached (INV-2).
pub fn finalize_expired_escrow(env: &Env, commitment: BytesN<32>) -> Result<(), QuickexError> {
    let commitment_bytes: Bytes = commitment.clone().into();
    let entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;

    // INV-5: terminal states are final (also catches a prior finalize_expired_escrow
    // or refund call — makes this function safe to call more than once).
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

    let token_ref = entry.token.clone();
    let owner_ref = entry.owner.clone();
    let amount_paid = entry.amount_paid;
    let expires_at = entry.expires_at;

    let mut updated = entry;
    updated.status = EscrowStatus::Refunded;
    put_escrow(env, &commitment_bytes, &updated);

    let token_client = token::Client::new(env, &token_ref);
    token_client.transfer(&env.current_contract_address(), &owner_ref, &amount_paid);

    events::publish_refund_finalized(
        env,
        commitment.clone(),
        owner_ref.clone(),
        token_ref.clone(),
        amount_paid,
        expires_at,
    );

    hook::invoke_hooks(
        env,
        HookEventKind::Refund,
        &commitment,
        owner_ref,
        token_ref,
        amount_paid,
        0,
    );

    Ok(())
}

/// Read-only check for whether an escrow is currently eligible for refund
/// finalization, without submitting a state-changing transaction.
///
/// Intended for dapps/keepers to poll before calling [`finalize_expired_escrow`],
/// and for indexers reconstructing refund availability off-chain (though note
/// [`events::publish_escrow_deposited`] already carries `expires_at`, so most
/// indexers can compute this themselves from the original deposit event).
///
/// Returns `false` (rather than erroring) once the escrow has already left
/// `Pending` — including after it has already been refunded — since it is no
/// longer eligible, not because eligibility couldn't be computed.
///
/// # Errors
/// - [`CommitmentNotFound`] – no escrow for the given commitment.
pub fn is_refund_eligible(env: &Env, commitment: BytesN<32>) -> Result<bool, QuickexError> {
    let commitment_bytes: Bytes = commitment.into();
    let entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;
    Ok(entry.status == EscrowStatus::Pending && is_expired(env, &entry))
}

// ---------------------------------------------------------------------------
// TTL & Cleanup
// ---------------------------------------------------------------------------

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
/// - In multi-sig mode (`arbiter_threshold > 0`), freezes a
///   [`dispute_quorum::DisputeQuorumSnapshot`] from the *current* admin
///   quorum policy (Issue #865 / SC-W8-04). Later changes to that policy
///   never affect this dispute.
///
/// # Errors
/// - [`CommitmentNotFound`] – no escrow for the given commitment.
/// - [`NoArbiter`] – no arbiter assigned to the escrow, or multi-sig mode is
///   flagged (`arbiter_threshold > 0`) with no arbiters assigned.
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

    // Guard: a multi-sig escrow must actually have arbiters to vote.
    if entry.arbiter_threshold > 0 && entry.arbiters.is_empty() {
        return Err(QuickexError::NoArbiter);
    }

    let mut updated = entry.clone();
    updated.status = EscrowStatus::Disputed;
    put_escrow(env, &commitment_bytes, &updated);

    if entry.arbiter_threshold > 0 {
        let disputed_at = env.ledger().timestamp();
        dispute_quorum::open_snapshot(env, &commitment_bytes, disputed_at, entry.arbiters.len());
    }

    events::publish_escrow_disputed(env, commitment, arbiter.clone());

    Ok(())
}

// ---------------------------------------------------------------------------
// resolve_dispute
// ---------------------------------------------------------------------------

/// Resolve a disputed escrow by determining the recipient of funds.
///
/// - Only callable by the assigned arbiter (or a globally authorized Arbiter role).
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
    nonce_val: u64,
    valid_until: u64,
) -> Result<(), QuickexError> {
    let commitment_bytes: Bytes = commitment.clone().into();
    let entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;

    // Guard: caller must be either the assigned arbiter OR have the global Arbiter role.
    caller.require_auth();

    nonce::verify_and_consume(
        env,
        &caller,
        nonce_val,
        valid_until,
        ActionType::ResolveDispute,
    )?;
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
        (EscrowStatus::Spent, recipient)
    };

    let mut updated = entry.clone();
    updated.status = final_status;
    put_escrow(env, &commitment_bytes, &updated);

    let fee_amount = if final_status == EscrowStatus::Spent {
        let (_payout_amount, fee) = fee_router::route_payout_price_aware(
            env,
            &entry.token,
            &recipient_address,
            entry.amount_paid,
            Some(&caller),
        )?;
        fee
    } else {
        // Refund path — no fee, direct transfer to owner.
        let token_client = token::Client::new(env, &entry.token);
        token_client.transfer(
            &env.current_contract_address(),
            &recipient_address,
            &entry.amount_paid,
        );
        0
    };

    if resolve_for_owner {
        events::publish_escrow_refunded(
            env,
            entry.owner.clone(),
            commitment.clone(),
            entry.token.clone(),
            entry.amount_paid,
        );
        hook::invoke_hooks(
            env,
            HookEventKind::Refund,
            &commitment,
            entry.owner.clone(),
            entry.token.clone(),
            entry.amount_paid,
            0,
        );
    } else {
        events::publish_escrow_withdrawn(
            env,
            commitment.clone(),
            recipient_address.clone(),
            entry.token.clone(),
            entry.amount_paid,
            fee_amount,
        );
        hook::invoke_hooks(
            env,
            HookEventKind::Settle,
            &commitment,
            entry.owner.clone(),
            entry.token,
            entry.amount_paid,
            fee_amount,
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// vote_for_dispute (multi-sig)
// ---------------------------------------------------------------------------

/// Get a dispute's frozen quorum snapshot, lazily computing one from the
/// current policy if this dispute predates the SC-W8-04 quorum feature.
///
/// A lazily-created snapshot is itself frozen from that point on — this only
/// bridges disputes opened by an older contract version; it never re-reads
/// the live config for a dispute that already has a snapshot.
fn ensure_quorum_snapshot(
    env: &Env,
    commitment_bytes: &Bytes,
    entry: &EscrowEntry,
) -> dispute_quorum::DisputeQuorumSnapshot {
    if let Some(snapshot) = dispute_quorum::get_snapshot(env, commitment_bytes) {
        return snapshot;
    }
    dispute_quorum::open_snapshot(
        env,
        commitment_bytes,
        env.ledger().timestamp(),
        entry.arbiters.len(),
    );
    dispute_quorum::get_snapshot(env, commitment_bytes)
        .expect("snapshot was just written unconditionally")
}

/// Cast a vote on a disputed escrow (multi-sig mode).
///
/// - Only callable by one of the assigned arbiters.
/// - Escrow must be in `Disputed` status.
/// - Each arbiter can only vote once per dispute.
/// - Does not resolve the dispute immediately; only records the vote.
/// - When quorum is reached, the dispute can be resolved via `resolve_dispute_multi_sig`.
/// - Voting closes at the dispute's frozen quorum-snapshot deadline
///   (Issue #865 / SC-W8-04); once quorum is missed past that point, see
///   `resolve_dispute_timeout`.
///
/// # Arguments
/// - `caller`: The arbiter casting the vote
/// - `commitment`: The escrow commitment hash
/// - `resolve_for_owner`: If `true`, voting to refund to owner; if `false`, voting to pay recipient
///
/// # Errors
/// - [`CommitmentNotFound`] – no escrow for the given commitment.
/// - [`InvalidDisputeState`] – escrow is not in `Disputed` status.
/// - [`NotAnArbiter`] – caller is not one of the assigned arbiters.
/// - [`ArbiterAlreadyVoted`] – caller has already voted on this dispute.
/// - [`InvalidDisputeState`] – also returned once the dispute's voting
///   deadline has passed (Issue #865 / SC-W8-04); reuses this code rather
///   than a dedicated variant to stay under Soroban's 50-case error-enum cap.
pub fn vote_for_dispute(
    env: &Env,
    caller: Address,
    commitment: BytesN<32>,
    resolve_for_owner: bool,
    nonce_val: u64,
    valid_until: u64,
) -> Result<(), QuickexError> {
    caller.require_auth();

    nonce::verify_and_consume(
        env,
        &caller,
        nonce_val,
        valid_until,
        ActionType::VoteForDispute,
    )?;

    let commitment_bytes: Bytes = commitment.clone().into();
    let entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;

    // Guard: escrow must be in Disputed state
    if entry.status != EscrowStatus::Disputed {
        return Err(QuickexError::InvalidDisputeState);
    }

    // Guard: must be in multi-sig mode (threshold > 0)
    if entry.arbiter_threshold == 0 {
        return Err(QuickexError::NoArbiter);
    }

    // Guard: caller must be one of the assigned arbiters
    let mut is_arbiter = false;
    for arbiter in entry.arbiters.iter() {
        if arbiter == caller {
            is_arbiter = true;
            break;
        }
    }

    // Also check global Arbiter role
    if !is_arbiter {
        is_arbiter = admin::has_role(env, &caller, Role::Arbiter);
    }

    if !is_arbiter {
        return Err(QuickexError::NotAnArbiter);
    }

    // Guard: arbiter must not have already voted
    if has_dispute_vote(env, &commitment_bytes, &caller) {
        return Err(QuickexError::ArbiterAlreadyVoted);
    }

    // Guard: voting closes at the dispute's frozen quorum deadline (SC-W8-04)
    let snapshot = ensure_quorum_snapshot(env, &commitment_bytes, &entry);
    if env.ledger().timestamp() > snapshot.deadline {
        return Err(QuickexError::InvalidDisputeState);
    }

    // Record the vote
    let vote = DisputeVote {
        arbiter: caller.clone(),
        resolve_for_owner,
        voted_at: env.ledger().timestamp(),
    };

    put_dispute_vote(env, &commitment_bytes, &caller, &vote);

    // Count fresh (non-expired) votes
    let vote_count = count_dispute_votes(
        env,
        &commitment_bytes,
        &entry.arbiters,
        snapshot.vote_ttl_secs,
    );

    // Emit vote cast event
    events::publish_arbiter_vote_cast(
        env,
        commitment,
        caller,
        resolve_for_owner,
        vote_count,
        snapshot.required_votes,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// resolve_dispute_multi_sig
// ---------------------------------------------------------------------------

/// Tally fresh (non-expired) votes for each side of a dispute.
fn tally_fresh_votes(
    env: &Env,
    commitment_bytes: &Bytes,
    arbiters: &Vec<Address>,
    vote_ttl_secs: u64,
) -> (u32, u32) {
    let now = env.ledger().timestamp();
    let mut votes_for_owner: u32 = 0;
    let mut votes_for_recipient: u32 = 0;

    for arbiter in arbiters.iter() {
        if let Some(vote) = get_dispute_vote(env, commitment_bytes, &arbiter) {
            if now > vote.voted_at.saturating_add(vote_ttl_secs) {
                continue; // expired; does not count toward quorum or the outcome
            }
            if vote.resolve_for_owner {
                votes_for_owner += 1;
            } else {
                votes_for_recipient += 1;
            }
        }
    }

    (votes_for_owner, votes_for_recipient)
}

/// Resolve a disputed escrow using multi-sig arbitration.
///
/// - Can be called by anyone once quorum is met.
/// - Escrow must be in `Disputed` status.
/// - Requires that the number of *fresh* votes >= the dispute's frozen quorum
///   snapshot (Issue #865 / SC-W8-04); expired votes count toward neither
///   quorum nor the outcome.
/// - Determines the outcome based on majority among fresh votes cast.
/// - If quorum cannot be reached before the snapshot's deadline, see
///   `resolve_dispute_timeout` for the fallback resolution path.
///
/// # Arguments
/// - `commitment`: The escrow commitment hash
/// - `recipient`: Address to receive funds when resolving for recipient
///
/// # Errors
/// - [`CommitmentNotFound`] – no escrow for the given commitment.
/// - [`InvalidDisputeState`] – escrow is not in `Disputed` status.
/// - [`InsufficientVotes`] – quorum has not been reached yet.
pub fn resolve_dispute_multi_sig(
    env: &Env,
    commitment: BytesN<32>,
    recipient: Address,
) -> Result<(), QuickexError> {
    let commitment_bytes: Bytes = commitment.clone().into();
    let entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;

    // Guard: escrow must be in Disputed state
    if entry.status != EscrowStatus::Disputed {
        return Err(QuickexError::InvalidDisputeState);
    }

    // Guard: must be in multi-sig mode
    if entry.arbiter_threshold == 0 {
        return Err(QuickexError::NoArbiter);
    }

    let snapshot = ensure_quorum_snapshot(env, &commitment_bytes, &entry);

    // Count fresh votes
    let vote_count = count_dispute_votes(
        env,
        &commitment_bytes,
        &entry.arbiters,
        snapshot.vote_ttl_secs,
    );

    // Guard: quorum must be met
    if vote_count < snapshot.required_votes {
        return Err(QuickexError::InsufficientVotes);
    }

    // Tally fresh votes for each side
    let (votes_for_owner, votes_for_recipient) = tally_fresh_votes(
        env,
        &commitment_bytes,
        &entry.arbiters,
        snapshot.vote_ttl_secs,
    );

    // Determine outcome by majority
    let resolve_for_owner = votes_for_owner >= votes_for_recipient;

    let (final_status, recipient_address) = if resolve_for_owner {
        (EscrowStatus::Refunded, entry.owner.clone())
    } else {
        (EscrowStatus::Spent, recipient)
    };

    let mut updated = entry.clone();
    updated.status = final_status;
    put_escrow(env, &commitment_bytes, &updated);

    let fee_amount = if final_status == EscrowStatus::Spent {
        let (_payout_amount, fee) = fee_router::route_payout_price_aware(
            env,
            &entry.token,
            &recipient_address,
            entry.amount_paid,
            None,
        )?;
        fee
    } else {
        let token_client = token::Client::new(env, &entry.token);
        token_client.transfer(
            &env.current_contract_address(),
            &recipient_address,
            &entry.amount_paid,
        );
        0
    };

    // Emit dispute resolved event
    events::publish_dispute_resolved(
        env,
        commitment.clone(),
        resolve_for_owner,
        vote_count,
        snapshot.required_votes,
        entry.amount_paid,
    );

    if resolve_for_owner {
        events::publish_escrow_refunded(
            env,
            entry.owner.clone(),
            commitment.clone(),
            entry.token.clone(),
            entry.amount_paid,
        );
        hook::invoke_hooks(
            env,
            HookEventKind::Refund,
            &commitment,
            entry.owner.clone(),
            entry.token.clone(),
            entry.amount_paid,
            0,
        );
    } else {
        events::publish_escrow_withdrawn(
            env,
            commitment.clone(),
            recipient_address.clone(),
            entry.token.clone(),
            entry.amount_paid,
            fee_amount,
        );
        hook::invoke_hooks(
            env,
            HookEventKind::Settle,
            &commitment,
            entry.owner.clone(),
            entry.token,
            entry.amount_paid,
            fee_amount,
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// resolve_dispute_timeout (quorum fallback)
// ---------------------------------------------------------------------------

/// Fallback resolution for a multi-sig dispute that missed quorum before its
/// voting deadline (Issue #865 / SC-W8-04 AC3).
///
/// Callable by anyone once the dispute's frozen quorum-snapshot deadline has
/// passed with too few fresh votes to resolve normally. Deterministically
/// refunds the owner — the same fail-closed default this contract uses
/// elsewhere (e.g. the oracle aggregator) when it cannot safely determine an
/// alternative outcome — so funds are never permanently stuck behind a
/// quorum arbiters failed to reach in time.
///
/// # Arguments
/// - `commitment`: The escrow commitment hash
///
/// # Errors
/// - [`CommitmentNotFound`] – no escrow for the given commitment.
/// - [`InvalidDisputeState`] – escrow is not in `Disputed` status; also
///   returned when the voting deadline has not passed yet, or when fresh
///   votes already meet quorum (call `resolve_dispute_multi_sig` instead).
///   These share one code rather than dedicated variants to stay under
///   Soroban's 50-case error-enum cap (Issue #865 / SC-W8-04).
/// - [`NoArbiter`] – not a multi-sig dispute.
pub fn resolve_dispute_timeout(env: &Env, commitment: BytesN<32>) -> Result<(), QuickexError> {
    let commitment_bytes: Bytes = commitment.clone().into();
    let entry: EscrowEntry =
        get_escrow(env, &commitment_bytes).ok_or(QuickexError::CommitmentNotFound)?;

    if entry.status != EscrowStatus::Disputed {
        return Err(QuickexError::InvalidDisputeState);
    }
    if entry.arbiter_threshold == 0 {
        return Err(QuickexError::NoArbiter);
    }

    let snapshot = ensure_quorum_snapshot(env, &commitment_bytes, &entry);

    // Fallback only applies past the deadline (SC-W8-04).
    if env.ledger().timestamp() <= snapshot.deadline {
        return Err(QuickexError::InvalidDisputeState);
    }

    let vote_count = count_dispute_votes(
        env,
        &commitment_bytes,
        &entry.arbiters,
        snapshot.vote_ttl_secs,
    );
    // If quorum is still reachable with fresh votes, the caller should use
    // `resolve_dispute_multi_sig` instead of forcing the owner-refund default.
    if vote_count >= snapshot.required_votes {
        return Err(QuickexError::InvalidDisputeState);
    }

    let mut updated = entry.clone();
    updated.status = EscrowStatus::Refunded;
    put_escrow(env, &commitment_bytes, &updated);

    let token_client = token::Client::new(env, &entry.token);
    token_client.transfer(
        &env.current_contract_address(),
        &entry.owner,
        &entry.amount_paid,
    );

    events::publish_dispute_quorum_timeout(
        env,
        commitment.clone(),
        vote_count,
        snapshot.required_votes,
        snapshot.deadline,
        entry.amount_paid,
    );
    events::publish_escrow_refunded(
        env,
        entry.owner.clone(),
        commitment.clone(),
        entry.token.clone(),
        entry.amount_paid,
    );
    hook::invoke_hooks(
        env,
        HookEventKind::Refund,
        &commitment,
        entry.owner.clone(),
        entry.token.clone(),
        entry.amount_paid,
        0,
    );

    Ok(())
}
