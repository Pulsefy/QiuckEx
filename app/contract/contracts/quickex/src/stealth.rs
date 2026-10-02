//! # Stealth Address – Proof of Concept (Issue #157 / Privacy v2)
//!
//! ## Overview
//!
//! Implements a stealth-address derivation proof of concept on Soroban.
//! This is **not Diffie-Hellman or a production stealth-address scheme**: the
//! contract hashes public byte strings because it does not perform elliptic-curve
//! operations. See `app/contract/docs/STEALTH_ADDRESS_DERIVATION.md` for the
//! byte-exact algorithm, vectors, and security limitations.
//!
//! ## Protocol (simplified dual-key stealth)
//!
//! ```text
//! Contract inputs:      (eph_pub, spend_pub)             [32 bytes each]
//!
//! Derivation (on-chain and reproducible off-chain):
//!   1. shared_secret = SHA-256(eph_pub || spend_pub)
//!   2. stealth_id    = SHA-256(spend_pub || shared_secret)
//!   3. Register the 32-byte stealth_id and lock funds under it.
//!
//! The contract uses `spend_pub` in place of a scan key; it does not derive a
//! spendable Stellar account or prove knowledge of a corresponding private key.
//! ```
//!
//! This is not an on-chain privacy guarantee. Contract invocation arguments are
//! public, including `spend_pub`; see the derivation document before integrating.

use soroban_sdk::{token, Address, Bytes, BytesN, Env};

use crate::{
    errors::QuickexError,
    events, fee_router,
    nonce::{self, ActionType},
    storage::{get_stealth_escrow, put_stealth_escrow},
    types::{EscrowStatus, StealthDepositParams, StealthEscrowEntry},
};

// ---------------------------------------------------------------------------
// Key-derivation helpers
// ---------------------------------------------------------------------------

/// Hash two 32-byte inputs in order to produce a 32-byte intermediate value.
///
/// `shared_secret = SHA-256(key_a || key_b)`.
/// This is a deterministic hash, not an ECDH shared secret.
pub fn derive_shared_secret(env: &Env, key_a: &BytesN<32>, key_b: &BytesN<32>) -> BytesN<32> {
    let mut payload = Bytes::new(env);
    payload.append(&Bytes::from(key_a.clone()));
    payload.append(&Bytes::from(key_b.clone()));
    env.crypto().sha256(&payload).into()
}

/// Derive the 32-byte stealth identifier from a spend key and intermediate hash.
///
/// `stealth_id = SHA-256(spend_pub || shared_secret)`.
/// The result is an escrow identifier, not a Stellar account address.
pub fn derive_stealth_address(
    env: &Env,
    spend_pub: &BytesN<32>,
    shared_secret: &BytesN<32>,
) -> BytesN<32> {
    let mut payload = Bytes::new(env);
    payload.append(&Bytes::from(spend_pub.clone()));
    payload.append(&Bytes::from(shared_secret.clone()));
    env.crypto().sha256(&payload).into()
}

// ---------------------------------------------------------------------------
// register_ephemeral_key
// ---------------------------------------------------------------------------

/// Register an ephemeral public key and lock funds for a stealth recipient.
///
/// The sender provides:
/// - `stealth_address` – the 32-byte identifier derived off-chain using the
///   documented two-stage SHA-256 construction.
/// - `eph_pub`         – the sender's ephemeral public key (32 bytes).
/// - `spend_pub`       – recipient spend-key bytes (32 bytes); this is public
///   transaction input and is not validated as a curve point.
///
/// The contract re-derives the identifier to verify the sender's computation,
/// then locks `amount` of `token` under that identifier. This check does not
/// establish ECDH key ownership or cryptographic unlinkability.
///
/// # Errors
/// - [`InvalidAmount`]            – amount ≤ 0.
/// - [`StealthAddressMismatch`]   – on-chain re-derivation does not match `stealth_address`.
/// - [`StealthAddressAlreadyUsed`]– a deposit already exists for this stealth address.
pub fn register_ephemeral_key(
    env: &Env,
    params: StealthDepositParams,
    nonce_val: u64,
    valid_until: u64,
) -> Result<BytesN<32>, QuickexError> {
    let StealthDepositParams {
        sender,
        token,
        amount_due,
        amount_paid,
        eph_pub,
        spend_pub,
        stealth_address,
        timeout_secs,
    } = params;

    if amount_due <= 0 || amount_paid <= 0 {
        return Err(QuickexError::InvalidAmount);
    }

    if amount_paid > amount_due {
        return Err(QuickexError::Overpayment);
    }

    sender.require_auth();

    nonce::verify_and_consume(
        env,
        &sender,
        nonce_val,
        valid_until,
        ActionType::StealthDeposit,
    )?;

    // Re-derive on-chain to verify the documented hash construction.
    // shared_secret = SHA-256(eph_pub || spend_pub)
    let shared_secret = derive_shared_secret(env, &eph_pub, &spend_pub);
    // stealth_id = SHA-256(spend_pub || shared_secret)
    let expected_stealth = derive_stealth_address(env, &spend_pub, &shared_secret);

    if expected_stealth != stealth_address {
        return Err(QuickexError::StealthAddressMismatch);
    }

    // Reject duplicate stealth addresses (replay protection).
    if get_stealth_escrow(env, &stealth_address).is_some() {
        return Err(QuickexError::StealthAddressAlreadyUsed);
    }

    // Transfer funds from sender to contract.
    let token_client = token::Client::new(env, &token);
    let contract_addr = env.current_contract_address();
    token_client.transfer(&sender, &contract_addr, &amount_paid);

    let now = env.ledger().timestamp();
    let expires_at = if timeout_secs > 0 {
        now.saturating_add(timeout_secs)
    } else {
        0
    };

    let entry = StealthEscrowEntry {
        token: token.clone(),
        amount_due,
        amount_paid,
        eph_pub: eph_pub.clone(),
        status: EscrowStatus::Pending,
        created_at: now,
        expires_at,
    };

    put_stealth_escrow(env, &stealth_address, &entry);

    events::publish_ephemeral_key_registered(
        env,
        stealth_address.clone(),
        eph_pub,
        token,
        amount_due,
        amount_paid,
        expires_at,
    );

    Ok(stealth_address)
}

// ---------------------------------------------------------------------------
// stealth_withdraw
// ---------------------------------------------------------------------------

/// Withdraw funds locked under a stealth address.
///
/// The caller supplies the same `spend_pub` and `eph_pub` used at registration.
/// Matching the derived identifier is not proof of private-key ownership:
/// actual authorization is provided by `recipient.require_auth()`.
///
/// The `recipient` address is public in the withdrawal invocation. It is not
/// cryptographically unlinkable from earlier activity.
///
/// This proof of concept is not safe for value-bearing deployments: observers
/// can reproduce the public derivation inputs and authorize their own recipient.
///
/// # Errors
/// - [`StealthEscrowNotFound`]  – no escrow for this stealth address.
/// - [`AlreadySpent`]           – escrow already withdrawn or refunded.
/// - [`EscrowExpired`]          – escrow has passed its expiry.
/// - [`StealthAddressMismatch`] – re-derived address does not match.
pub fn stealth_withdraw(
    env: &Env,
    recipient: Address,
    eph_pub: BytesN<32>,
    spend_pub: BytesN<32>,
    stealth_address: BytesN<32>,
    nonce_val: u64,
    valid_until: u64,
) -> Result<bool, QuickexError> {
    recipient.require_auth();

    nonce::verify_and_consume(
        env,
        &recipient,
        nonce_val,
        valid_until,
        ActionType::StealthWithdraw,
    )?;

    let mut entry =
        get_stealth_escrow(env, &stealth_address).ok_or(QuickexError::StealthEscrowNotFound)?;

    if entry.status != EscrowStatus::Pending {
        return Err(QuickexError::AlreadySpent);
    }

    if entry.expires_at > 0 && env.ledger().timestamp() >= entry.expires_at {
        return Err(QuickexError::EscrowExpired);
    }

    // Verify the caller knows the correct spend_pub for this stealth address.
    let shared_secret = derive_shared_secret(env, &eph_pub, &spend_pub);
    let expected_stealth = derive_stealth_address(env, &spend_pub, &shared_secret);

    if expected_stealth != stealth_address {
        return Err(QuickexError::StealthAddressMismatch);
    }

    // Mark spent before transfer (checks-effects-interactions).
    entry.status = EscrowStatus::Spent;
    put_stealth_escrow(env, &stealth_address, &entry);

    // Route payout through fee system, honoring per-asset overrides and oracle pricing.
    let (_payout_amount, fee_amount) = fee_router::route_payout_price_aware(
        env,
        &entry.token,
        &recipient,
        entry.amount_paid,
        None,
    )?;

    events::publish_stealth_withdrawn(
        env,
        stealth_address,
        recipient,
        entry.token,
        entry.amount_paid,
        fee_amount,
    );

    Ok(true)
}

// ---------------------------------------------------------------------------
// get_stealth_escrow_status (read-only)
// ---------------------------------------------------------------------------

/// Return the status of a stealth escrow without revealing sensitive fields.
///
/// Returns `None` if no escrow exists for the given stealth address.
pub fn get_stealth_status(env: &Env, stealth_address: &BytesN<32>) -> Option<EscrowStatus> {
    get_stealth_escrow(env, stealth_address).map(|e| e.status)
}
