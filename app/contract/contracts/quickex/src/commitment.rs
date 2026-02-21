use crate::errors::QuickexError;
use soroban_sdk::{xdr::ToXdr, Address, Bytes, BytesN, Env};

/// # Commitment Scheme Invariants
///
/// This module implements a cryptographic commitment scheme for privacy-preserving
/// escrow transactions. The following invariants are guaranteed:
///
/// ## Core Invariants
///
/// 1. **Determinism**: Same (owner, amount, salt) → same commitment
///    - Given identical inputs, the commitment hash is always identical
///    - This enables verification without revealing the preimage
///
/// 2. **Collision Resistance**: Different inputs → different commitments (with overwhelming probability)
///    - Changing owner → different commitment
///    - Changing amount → different commitment
///    - Changing salt → different commitment
///    - SHA-256 provides ~2^256 output space, making collisions computationally infeasible
///
/// 3. **Hiding Property**: Commitment reveals nothing about (owner, amount, salt)
///    - The SHA-256 hash is cryptographically one-way
///    - No practical algorithm can derive inputs from the commitment alone
///    - Salt adds entropy to prevent rainbow table attacks on common amounts
///
/// 4. **Binding Property**: Once created, a commitment cannot be opened to different values
///    - The commitment binds the creator to specific (owner, amount, salt)
///    - Verification will fail for any other combination
///
/// ## Security Constraints
///
/// - Amount must be non-negative (amount >= 0)
/// - Salt length capped at 1024 bytes to prevent DoS via excessive hashing
/// - Uses XDR serialization for Address to ensure canonical representation
/// - Big-endian encoding for amount ensures consistent byte ordering
///
/// ## Limitations
///
/// - No formal cryptographic proof provided in-code (empirical testing only)
/// - Relies on SHA-256 security assumptions (pre-image resistance, collision resistance)
/// - Salt must be kept secret by the user; if leaked, privacy is compromised
/// - Does not protect against timing attacks (constant-time operations not guaranteed)
///
/// ## Implementation Details
///
/// Commitment = SHA256(XDR(owner) || BE(amount) || salt)
/// where:
/// - XDR(owner) = Stellar XDR encoding of Address
/// - BE(amount) = 16-byte big-endian representation of i128
/// - || = byte concatenation
///
pub fn create_amount_commitment(
    env: &Env,
    owner: Address,
    amount: i128,
    salt: Bytes,
) -> Result<BytesN<32>, QuickexError> {
    if amount < 0 {
        return Err(QuickexError::InvalidAmount);
    }

    // Cap salt length as a safeguard
    if salt.len() > 1024 {
        return Err(QuickexError::InvalidSalt);
    }

    let mut payload = Bytes::new(env);

    // Append owner (Address) - using XDR serialization for consistency
    payload.append(&owner.to_xdr(env));

    // Serialize amount (i128) to big-endian bytes
    let amount_bytes: [u8; 16] = amount.to_be_bytes();

    // Correct loop iteration over bytes
    for b in &amount_bytes {
        payload.push_back(*b);
    }

    // Append salt
    payload.append(&salt);

    // Return SHA256 hash
    Ok(env.crypto().sha256(&payload).into())
}

pub fn verify_amount_commitment(
    env: &Env,
    commitment: BytesN<32>,
    owner: Address,
    amount: i128,
    salt: Bytes,
) -> bool {
    match create_amount_commitment(env, owner, amount, salt) {
        Ok(hash) => hash == commitment,
        Err(_) => false,
    }
}
