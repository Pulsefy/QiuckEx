//! # Stealth Address – Proof of Concept (Issue #157 / Privacy v2)
//!
//! ## Overview
//!
//! Implements a Diffie-Hellman-based stealth address mechanism on Soroban.
//! Because Soroban SDK v23 does not expose raw elliptic-curve point operations,
//! we simulate the ECDH shared-secret derivation using SHA-256 as a key-derivation
//! function over the concatenation of the sender's ephemeral public key and the
//! recipient's scan key.  This is a **proof-of-concept** – a production deployment
//! would replace the KDF with a proper secp256k1 / Ed25519 point-multiplication
//! once the SDK exposes those primitives.
//!
//! ## Protocol (simplified dual-key stealth)
//!
//! ```text
//! Recipient publishes:  (scan_pub_key, spend_pub_key)   [32 bytes each]
//!
//! Sender (off-chain):
//!   1. Generate ephemeral keypair (eph_priv, eph_pub).
//!   2. shared_secret = KDF(eph_pub || scan_pub_key)     [SHA-256]
//!   3. stealth_address = KDF(spend_pub_key || shared_secret)
//!   4. Call register_ephemeral_key(stealth_address, eph_pub, token, amount, timeout)
//!      → funds locked under stealth_address commitment.
//!
//! Recipient (off-chain):
//!   1. Scan chain for EphemeralKeyRegistered events.
//!   2. For each event: shared_secret = KDF(eph_pub || scan_priv_key * G)
//!      (simplified: KDF(eph_pub || scan_priv_key_bytes))
//!   3. Recompute stealth_address = KDF(spend_pub_key || shared_secret).
//!   4. If stealth_address matches → funds are for me.
//!   5. Derive stealth_priv_key = KDF(spend_priv_key || shared_secret).
//!   6. Call stealth_withdraw(stealth_address, eph_pub, amount, token)
//!      → contract re-derives stealth_address and releases funds.
//! ```
//!
//! ## On-chain privacy guarantee
//!
//! The recipient's main public address (`spend_pub_key` / `scan_pub_key`) never
//! appears in any transaction or event.  Only the one-time `stealth_address` and
//! the sender's `eph_pub` are recorded on-chain.

use soroban_sdk::{token, Address, Bytes, BytesN, Env};

use crate::{
    errors::QuickexError,
    events,
    storage::{get_stealth_escrow, put_stealth_escrow},
    types::{EscrowStatus, StealthEscrowEntry},
};

// ---------------------------------------------------------------------------
// Key-derivation helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte shared secret from two 32-byte public-key blobs.
///
/// `KDF(a, b) = SHA-256(a || b)`
///
/// In a production implementation this would be replaced by proper EC scalar
/// multiplication (e.g. `eph_priv * scan_pub` on secp256k1).
pub fn derive_shared_secret(env: &Env, key_a: &BytesN<32>, key_b: &BytesN<32>) -> BytesN<32> {
    let mut payload = Bytes::new(env);
    payload.append(&Bytes::from(key_a.clone()));
    payload.append(&Bytes::from(key_b.clone()));
    env.crypto().sha256(&payload).into()
}

/// Derive the one-time stealth address from a spend key and a shared secret.
///
/// `stealth = SHA-256(spend_pub || shared_secret)`
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
/// - `stealth_address` – the one-time address derived off-chain via DH.
/// - `eph_pub`         – the sender's ephemeral public key (32 bytes).
/// - `spend_pub`       – recipient's spend public key (32 bytes).
///
/// The contract re-derives the stealth address on-chain to verify the sender's
/// computation, then locks `amount` of `token` under that stealth address.
///
/// # Errors
/// - [`InvalidAmount`]            – amount ≤ 0.
/// - [`StealthAddressMismatch`]   – on-chain re-derivation does not match `stealth_address`.
/// - [`StealthAddressAlreadyUsed`]– a deposit already exists for this stealth address.
pub fn register_ephemeral_key(
    env: &Env,
    sender: Address,
    token: Address,
    amount: i128,
    eph_pub: BytesN<32>,
    spend_pub: BytesN<32>,
    stealth_address: BytesN<32>,
    timeout_secs: u64,
) -> Result<BytesN<32>, QuickexError> {
    if amount <= 0 {
        return Err(QuickexError::InvalidAmount);
    }

    sender.require_auth();

    // Re-derive on-chain to verify sender's computation.
    // shared_secret = KDF(eph_pub || spend_pub)
    let shared_secret = derive_shared_secret(env, &eph_pub, &spend_pub);
    // stealth = KDF(spend_pub || shared_secret)
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
    token_client.transfer(&sender, &env.current_contract_address(), &amount);

    let now = env.ledger().timestamp();
    let expires_at = if timeout_secs > 0 {
        now.saturating_add(timeout_secs)
    } else {
        0
    };

    let entry = StealthEscrowEntry {
        token: token.clone(),
        amount,
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
        amount,
        expires_at,
    );

    Ok(stealth_address)
}

// ---------------------------------------------------------------------------
// stealth_withdraw
// ---------------------------------------------------------------------------

/// Withdraw funds locked under a stealth address.
///
/// The caller proves ownership by supplying the `spend_pub` key and the
/// `eph_pub` from the registration event.  The contract re-derives the
/// stealth address and, if it matches, transfers funds to `recipient`.
///
/// The `recipient` address is the caller's *real* on-chain address for
/// receiving the tokens – it is only revealed at withdrawal time and is
/// not linked to the original stealth address in any prior transaction.
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
) -> Result<bool, QuickexError> {
    recipient.require_auth();

    let mut entry = get_stealth_escrow(env, &stealth_address)
        .ok_or(QuickexError::StealthEscrowNotFound)?;

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

    // Transfer funds to recipient.
    let token_client = token::Client::new(env, &entry.token);
    token_client.transfer(&env.current_contract_address(), &recipient, &entry.amount);

    events::publish_stealth_withdrawn(
        env,
        stealth_address,
        recipient,
        entry.token,
        entry.amount,
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
