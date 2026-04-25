//! Deterministic Escrow ID derivation (Issue #304).
//!
//! # Purpose
//!
//! Derive a stable `escrow_id` from a canonical hash of the full escrow
//! creation payload. This enables deduplication of identical creation
//! requests and improves UX when the same request is re-submitted.
//!
//! # Design
//!
//! ```text
//! escrow_id = SHA-256(
//!     DOMAIN_TAG
//!     || be32(len(token_xdr))    || token_xdr
//!     || be128(amount)
//!     || be32(len(owner_xdr))    || owner_xdr
//!     || be64(timeout_secs)
//!     || arbiter_tag_u8          // 0 = None, 1 = Some
//!     || [ be32(len(arbiter_xdr)) || arbiter_xdr ]   // only if Some
//!     || be32(len(salt))         || salt
//! )
//! ```
//!
//! ## Invariants
//!
//! 1. **Determinism**: identical inputs always yield the same `escrow_id`.
//! 2. **Collision resistance**: different inputs yield different `escrow_id`
//!    with negligible probability (SHA-256).
//! 3. **Domain separation**: `DOMAIN_TAG` prevents cross-protocol collisions
//!    with the amount-commitment hash ([`crate::commitment`]) and the
//!    stealth-address hash ([`crate::stealth`]). Neither scheme uses this
//!    tag, so an `escrow_id` cannot equal any commitment or stealth address
//!    under a chosen-input attack.
//! 4. **Unambiguous boundaries**: every variable-length field (addresses,
//!    salt) carries a 4-byte big-endian length prefix, so no two distinct
//!    parameter tuples can produce the same byte stream.
//! 5. **Salt length cap**: enforced at 1024 bytes (matches
//!    [`crate::commitment`]) to guard against DoS-by-hashing.
//!
//! # What this is NOT
//!
//! - Not a privacy commitment. The `escrow_id` binds ALL creation params
//!   (token, timeout, arbiter) and is intended to be public, not hiding.
//! - Not a replacement for [`crate::commitment::create_amount_commitment`],
//!   which remains the privacy-preserving storage key for escrow entries.

use soroban_sdk::{xdr::ToXdr, Address, Bytes, BytesN, Env};

use crate::errors::QuickexError;

/// Domain separation tag for escrow-id derivation.
///
/// Bump the version suffix (`v1` → `v2`) if the canonical encoding ever
/// changes; this guarantees that clients and storage from different
/// versions cannot collide.
pub const ESCROW_ID_DOMAIN_TAG: &[u8] = b"QUICKEX::ESCROW_ID::v1";

/// Arbiter presence tag for canonical serialization.
const ARBITER_TAG_NONE: u8 = 0;
const ARBITER_TAG_SOME: u8 = 1;

/// Salt length cap (matches `commitment::create_amount_commitment`).
const MAX_SALT_LEN: u32 = 1024;

/// Append a variable-length byte field with a 4-byte big-endian length prefix.
///
/// The prefix makes field boundaries unambiguous, so two distinct parameter
/// tuples cannot produce the same serialized payload (INV-4).
fn append_len_prefixed(env: &Env, payload: &mut Bytes, field: &Bytes) {
    let len = field.len();
    payload.append(&Bytes::from_array(env, &len.to_be_bytes()));
    payload.append(field);
}

/// Derive a deterministic 32-byte escrow id from the full creation payload.
///
/// See the module doc for the exact canonical serialization and the
/// invariants it guarantees.
///
/// # Errors
///
/// - [`QuickexError::InvalidAmount`] if `amount < 0`.
/// - [`QuickexError::InvalidSalt`] if `salt.len() > 1024`.
pub fn derive_escrow_id(
    env: &Env,
    token: &Address,
    amount: i128,
    owner: &Address,
    salt: &Bytes,
    timeout_secs: u64,
    arbiter: &Option<Address>,
) -> Result<BytesN<32>, QuickexError> {
    if amount < 0 {
        return Err(QuickexError::InvalidAmount);
    }
    if salt.len() > MAX_SALT_LEN {
        return Err(QuickexError::InvalidSalt);
    }

    let mut payload = Bytes::new(env);

    // 1. Domain-separation tag.
    payload.append(&Bytes::from_slice(env, ESCROW_ID_DOMAIN_TAG));

    // 2. Token address (length-prefixed XDR).
    let token_xdr = token.to_xdr(env);
    append_len_prefixed(env, &mut payload, &token_xdr);

    // 3. Amount as big-endian i128 (16 bytes, fixed width → no prefix needed).
    let amount_bytes: [u8; 16] = amount.to_be_bytes();
    payload.append(&Bytes::from_array(env, &amount_bytes));

    // 4. Owner address (length-prefixed XDR).
    let owner_xdr = owner.to_xdr(env);
    append_len_prefixed(env, &mut payload, &owner_xdr);

    // 5. Timeout as big-endian u64 (8 bytes, fixed width).
    let timeout_bytes: [u8; 8] = timeout_secs.to_be_bytes();
    payload.append(&Bytes::from_array(env, &timeout_bytes));

    // 6. Optional arbiter: 1-byte tag + (length-prefixed XDR if Some).
    match arbiter {
        None => {
            payload.append(&Bytes::from_array(env, &[ARBITER_TAG_NONE]));
        }
        Some(arb) => {
            payload.append(&Bytes::from_array(env, &[ARBITER_TAG_SOME]));
            let arb_xdr = arb.to_xdr(env);
            append_len_prefixed(env, &mut payload, &arb_xdr);
        }
    }

    // 7. Salt (length-prefixed).
    append_len_prefixed(env, &mut payload, salt);

    Ok(env.crypto().sha256(&payload).into())
}
