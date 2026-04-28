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
///    - Keccak-256 provides ~2^256 output space, making collisions computationally infeasible
///
/// 3. **Hiding Property**: Commitment reveals nothing about (owner, amount, salt)
///    - The Keccak-256 hash is cryptographically one-way
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
/// - Relies on Keccak-256 security assumptions (pre-image resistance, collision resistance)
/// - Salt must be kept secret by the user; if leaked, privacy is compromised
/// - Does not protect against timing attacks (constant-time operations not guaranteed)
///
/// ## Implementation Details
///
/// Commitment = KECCAK256(XDR(owner) || BE(amount) || salt)
/// where:
/// - XDR(owner) = Stellar XDR encoding of Address
/// - BE(amount) = 16-byte big-endian representation of i128
/// - || = byte concatenation
///
/// Verification paths also accept the legacy `SHA256(XDR(owner) || BE(amount) || salt)`
/// commitment so older privacy escrows remain valid after the migration.
fn validate_commitment_input(amount: i128, salt: &Bytes) -> Result<(), QuickexError> {
    if amount < 0 {
        return Err(QuickexError::InvalidAmount);
    }
    if salt.len() > 1024 {
        return Err(QuickexError::InvalidSalt);
    }
    Ok(())
}

fn build_commitment_payload(env: &Env, owner: &Address, amount: i128, salt: &Bytes) -> Bytes {
    let mut payload = Bytes::new(env);
    payload.append(&owner.to_xdr(env));
    payload.append(&Bytes::from_array(env, &amount.to_be_bytes()));
    payload.append(salt);
    payload
}

pub(crate) fn amount_commitment_hashes(
    env: &Env,
    owner: &Address,
    amount: i128,
    salt: &Bytes,
) -> Result<(BytesN<32>, BytesN<32>), QuickexError> {
    validate_commitment_input(amount, salt)?;
    let payload = build_commitment_payload(env, owner, amount, salt);
    Ok((
        env.crypto().keccak256(&payload).into(),
        env.crypto().sha256(&payload).into(),
    ))
}

pub fn create_amount_commitment(
    env: &Env,
    owner: Address,
    amount: i128,
    salt: Bytes,
) -> Result<BytesN<32>, QuickexError> {
    let (commitment, _) = amount_commitment_hashes(env, &owner, amount, &salt)?;
    Ok(commitment)
}

pub fn verify_amount_commitment(
    env: &Env,
    commitment: BytesN<32>,
    owner: Address,
    amount: i128,
    salt: Bytes,
) -> bool {
    match amount_commitment_hashes(env, &owner, amount, &salt) {
        Ok((keccak, sha256)) => commitment == keccak || commitment == sha256,
        Err(_) => false,
    }
}
