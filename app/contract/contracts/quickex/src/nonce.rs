//! # Signature Replay Protection & Nonce Registry
//!
//! Provides replay protection for any signature-based flow by enforcing:
//!
//! 1. **Per-signer nonce uniqueness** — each `(signer, nonce)` pair can only be
//!    consumed once. Replaying the same nonce fails with [`QuickexError::NonceAlreadyUsed`].
//!
//! 2. **Expiry window** — the signed message carries a `valid_until` ledger
//!    timestamp. Submitting after that timestamp fails with
//!    [`QuickexError::SignatureExpired`].
//!
//! 3. **Domain separation** — the payload that callers sign must include the
//!    contract's own address and the network passphrase so that a signature
//!    produced for one contract / network cannot be replayed on another.
//!
//! ## Usage
//!
//! ```rust,ignore
//! // Build the domain-separated payload off-chain:
//! //   SHA256(contract_id || network_passphrase || nonce || valid_until || ...app_data)
//!
//! // On-chain, call before processing the signed action:
//! nonce::verify_and_consume(
//!     &env,
//!     &signer,
//!     nonce,
//!     valid_until,
//! )?;
//! ```
//!
//! ## Storage
//!
//! Consumed nonces are stored under [`DataKey::Nonce`]`(signer, nonce)` in
//! **persistent** storage with a 6-month TTL. This prevents the registry from
//! growing unboundedly while still covering any realistic replay window.

use soroban_sdk::{contracttype, Address, Env};

use crate::errors::QuickexError;
use crate::storage::{LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS};

// ---------------------------------------------------------------------------
// Storage key
// ---------------------------------------------------------------------------

/// Storage key for a consumed nonce.
///
/// Stored as `(signer_address, nonce_value) → true` in persistent storage.
#[contracttype]
#[derive(Clone)]
pub enum NonceKey {
    /// Marks that `signer` has consumed `nonce`.
    Used(Address, u64),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify that `nonce` has not been used by `signer` and that the current
/// ledger timestamp is strictly before `valid_until`, then mark the nonce as
/// consumed.
///
/// # Errors
///
/// | Error | Condition |
/// |-------|-----------|
/// | [`QuickexError::NonceAlreadyUsed`] | `(signer, nonce)` already consumed |
/// | [`QuickexError::SignatureExpired`] | `env.ledger().timestamp() >= valid_until` |
pub fn verify_and_consume(
    env: &Env,
    signer: &Address,
    nonce: u64,
    valid_until: u64,
) -> Result<(), QuickexError> {
    // 1. Expiry check — reject if the window has closed.
    if env.ledger().timestamp() >= valid_until {
        return Err(QuickexError::SignatureExpired);
    }

    // 2. Replay check — reject if this nonce was already consumed.
    let key = NonceKey::Used(signer.clone(), nonce);
    if env.storage().persistent().has(&key) {
        return Err(QuickexError::NonceAlreadyUsed);
    }

    // 3. Consume — mark as used with a 6-month TTL.
    env.storage().persistent().set(&key, &true);
    env.storage()
        .persistent()
        .extend_ttl(&key, LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS);

    Ok(())
}

/// Returns `true` if `(signer, nonce)` has already been consumed.
///
/// Useful for off-chain pre-flight checks.
pub fn is_nonce_used(env: &Env, signer: &Address, nonce: u64) -> bool {
    let key = NonceKey::Used(signer.clone(), nonce);
    env.storage().persistent().has(&key)
}

// ---------------------------------------------------------------------------
// Domain-separation helpers
// ---------------------------------------------------------------------------

/// Build the canonical domain-separated signing payload.
///
/// Callers sign `SHA256(contract_id || network_passphrase || nonce || valid_until || app_data)`
/// off-chain. This function returns the prefix bytes that must be included so
/// that the signature is bound to this specific contract and network.
///
/// The returned `Bytes` is:
/// ```text
/// contract_address_bytes (32) || network_passphrase_bytes (variable)
/// ```
///
/// Append your application-specific data before hashing.
pub fn domain_prefix(env: &Env) -> soroban_sdk::Bytes {
    use soroban_sdk::Bytes;

    let contract_bytes = env.current_contract_address().to_xdr(env);
    let passphrase = env.ledger().network_passphrase();

    let mut prefix = Bytes::new(env);
    prefix.append(&contract_bytes);
    prefix.append(&passphrase);
    prefix
}
