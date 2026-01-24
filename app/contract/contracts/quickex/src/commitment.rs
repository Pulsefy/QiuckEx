//! # Amount Commitment Module
//!
//! Placeholder commitment functions for X-Ray privacy features.
//! Provides deterministic hashing of amount commitments without real ZK proofs.
//!
//! ## Design
//! This module implements a commitment scheme using SHA256 hashing as a placeholder
//! for future zero-knowledge proof integration. Commitments are computed over:
//! - Owner address bytes
//! - Amount value (big-endian i128)
//! - Salt bytes
//!
//! ## Security Notice
//! These are NOT cryptographic commitments in the ZK sense. This implementation is
//! a deterministic placeholder to shape APIs and UX. Real privacy guarantees will
//! require integration with proper zero-knowledge proof systems.
//!
//! Future: Replace with actual ZK commitments (e.g., Pedersen, Poseidon hash).

use soroban_sdk::{Address, Bytes, Env, xdr::ToXdr};

/// Maximum allowed salt length (256 bytes) as a safeguard
const MAX_SALT_LENGTH: u32 = 256;

/// Create an amount commitment via deterministic SHA256 hashing.
///
/// Serializes the owner address, amount (big-endian i128), and salt into a byte
/// buffer, then computes SHA256 hash as the commitment. Useful for shaping APIs
/// before full ZK integration.
///
/// # Arguments
/// * `env` - The contract environment
/// * `owner` - The owner's address (included in commitment for domain separation)
/// * `amount` - The amount value (must be non-negative; negative amounts will panic)
/// * `salt` - Random bytes for uniqueness (length must not exceed MAX_SALT_LENGTH)
///
/// # Returns
/// * `Bytes` - SHA256 hash of serialized (owner || amount || salt)
///
/// # Panics
/// * If amount is negative
/// * If salt length exceeds MAX_SALT_LENGTH
///
/// # Example
/// ```ignore
/// let owner = Address::generate(&env);
/// let amount = 1_000_000i128;
/// let salt = Bytes::from_slice(&env, &[1, 2, 3, 4]);
/// let commitment = create_amount_commitment(&env, &owner, amount, &salt);
/// ```
pub fn create_amount_commitment(env: &Env, owner: &Address, amount: i128, salt: Bytes) -> Bytes {
    // Validation: amount must be non-negative
    if amount < 0 {
        panic!("Amount must be non-negative");
    }

    // Validation: salt length must not exceed maximum
    if salt.len() > MAX_SALT_LENGTH {
        panic!("Salt length exceeds maximum allowed");
    }

    // Add owner address bytes
    let owner_bytes = owner.to_xdr(env);

    // Add amount as big-endian i128 (16 bytes)
    let amount_bytes = amount.to_be_bytes();

    // Total: owner_bytes.len() + 16 (amount) + salt.len()
    let total_len: usize = (owner_bytes.len() + 16 + salt.len()) as usize;

    // Allocate a temporary buffer using the stack for small sizes or inline approach
    // Since we can't use std::vec, construct bytes manually
    let mut buffer = [0u8; 2048]; // Maximum reasonable size
    let mut offset = 0usize;

    // Copy owner bytes
    for i in 0..owner_bytes.len() {
        buffer[offset] = owner_bytes.get(i).unwrap();
        offset += 1;
    }

    // Copy amount bytes
    for i in 0..16 {
        buffer[offset] = amount_bytes[i];
        offset += 1;
    }

    // Copy salt bytes
    for i in 0..salt.len() {
        buffer[offset] = salt.get(i).unwrap();
        offset += 1;
    }

    // Create Bytes from the filled buffer
    let data = Bytes::from_slice(env, &buffer[0..total_len]);

    // Compute and return SHA256 hash
    env.crypto().sha256(&data).into()
}

/// Verify an amount commitment against claimed values.
///
/// Recomputes the commitment from the provided amount and salt, then compares
/// against the given commitment bytes. Returns true only if they match exactly.
///
/// # Arguments
/// * `env` - The contract environment
/// * `commitment` - The commitment bytes to verify
/// * `owner` - The owner's address
/// * `amount` - The claimed amount value
/// * `salt` - The claimed salt bytes
///
/// # Returns
/// * `bool` - True if commitment matches recomputed hash; false otherwise
///
/// # Example
/// ```ignore
/// let owner = Address::generate(&env);
/// let amount = 1_000_000i128;
/// let salt = Bytes::from_slice(&env, &[1, 2, 3, 4]);
/// let commitment = create_amount_commitment(&env, &owner, amount, &salt);
///
/// // Should succeed
/// assert!(verify_amount_commitment(&env, &commitment, &owner, amount, &salt));
///
/// // Should fail (tampered amount)
/// assert!(!verify_amount_commitment(&env, &commitment, &owner, amount + 1, &salt));
/// ```
pub fn verify_amount_commitment(
    env: &Env,
    commitment: &Bytes,
    owner: &Address,
    amount: i128,
    salt: Bytes,
) -> bool {
    // Recompute commitment with claimed values
    let recomputed = create_amount_commitment(env, owner, amount, salt);

    // Compare byte-for-byte
    commitment == &recomputed
}

/// Helper: Concatenate two Bytes objects.
///
/// Soroban's Bytes type doesn't natively support concatenation, so we reconstruct
/// by reading both sources and appending them sequentially.
#[deprecated = "No longer used; concat logic integrated into create_amount_commitment"]
fn _concat_bytes(env: &Env, a: &Bytes, b: &Bytes) -> Bytes {
    let total_len: usize = (a.len() + b.len()) as usize;
    let mut buffer = [0u8; 2048];
    let mut offset = 0usize;

    // Copy bytes from `a`
    for i in 0..a.len() {
        buffer[offset] = a.get(i).unwrap();
        offset += 1;
    }

    // Copy bytes from `b`
    for i in 0..b.len() {
        buffer[offset] = b.get(i).unwrap();
        offset += 1;
    }

    Bytes::from_slice(env, &buffer[0..total_len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn setup() -> Env {
        Env::default()
    }

    #[test]
    fn test_create_and_verify_commitment_success() {
        let env = setup();
        let owner = Address::generate(&env);
        let amount = 1_000_000i128;
        let salt = Bytes::from_slice(&env, &[1, 2, 3, 4, 5]);

        let commitment = create_amount_commitment(&env, &owner, amount, salt.clone());

        // Commitment should be 32 bytes (SHA256)
        assert_eq!(commitment.len(), 32);

        // Verification with same values should succeed
        assert!(verify_amount_commitment(
            &env,
            &commitment,
            &owner,
            amount,
            salt
        ));
    }

    #[test]
    fn test_verify_with_tampered_amount() {
        let env = setup();
        let owner = Address::generate(&env);
        let amount = 1_000_000i128;
        let salt = Bytes::from_slice(&env, &[1, 2, 3, 4, 5]);

        let commitment = create_amount_commitment(&env, &owner, amount, salt.clone());

        // Verification with different amount should fail
        assert!(!verify_amount_commitment(
            &env,
            &commitment,
            &owner,
            amount + 1,
            salt.clone()
        ));

        assert!(!verify_amount_commitment(
            &env,
            &commitment,
            &owner,
            amount - 1,
            salt
        ));
    }

    #[test]
    fn test_verify_with_tampered_salt() {
        let env = setup();
        let owner = Address::generate(&env);
        let amount = 1_000_000i128;
        let salt = Bytes::from_slice(&env, &[1, 2, 3, 4, 5]);

        let commitment = create_amount_commitment(&env, &owner, amount, salt.clone());

        // Verification with different salt should fail
        let tampered_salt = Bytes::from_slice(&env, &[1, 2, 3, 4, 6]);
        assert!(!verify_amount_commitment(
            &env,
            &commitment,
            &owner,
            amount,
            tampered_salt
        ));

        let empty_salt = Bytes::new(&env);
        assert!(!verify_amount_commitment(
            &env,
            &commitment,
            &owner,
            amount,
            empty_salt
        ));
    }

    #[test]
    fn test_verify_with_different_owner() {
        let env = setup();
        let owner1 = Address::generate(&env);
        let owner2 = Address::generate(&env);
        let amount = 1_000_000i128;
        let salt = Bytes::from_slice(&env, &[1, 2, 3, 4, 5]);

        let commitment = create_amount_commitment(&env, &owner1, amount, salt.clone());

        // Verification with different owner should fail
        assert!(!verify_amount_commitment(
            &env,
            &commitment,
            &owner2,
            amount,
            salt
        ));
    }

    #[test]
    fn test_zero_amount() {
        let env = setup();
        let owner = Address::generate(&env);
        let amount = 0i128;
        let salt = Bytes::from_slice(&env, &[42]);

        let commitment = create_amount_commitment(&env, &owner, amount, salt.clone());

        assert_eq!(commitment.len(), 32);
        assert!(verify_amount_commitment(
            &env,
            &commitment,
            &owner,
            amount,
            salt
        ));
    }

    #[test]
    fn test_empty_salt() {
        let env = setup();
        let owner = Address::generate(&env);
        let amount = 500i128;
        let salt = Bytes::new(&env);

        let commitment = create_amount_commitment(&env, &owner, amount, salt.clone());

        assert_eq!(commitment.len(), 32);
        assert!(verify_amount_commitment(
            &env,
            &commitment,
            &owner,
            amount,
            salt
        ));
    }

    #[test]
    fn test_large_amount() {
        let env = setup();
        let owner = Address::generate(&env);
        let amount = i128::MAX;
        let salt = Bytes::from_slice(&env, &[99, 88, 77]);

        let commitment = create_amount_commitment(&env, &owner, amount, salt.clone());

        assert_eq!(commitment.len(), 32);
        assert!(verify_amount_commitment(
            &env,
            &commitment,
            &owner,
            amount,
            salt
        ));
    }

    #[test]
    fn test_deterministic_hashing() {
        let env = setup();
        let owner = Address::generate(&env);
        let amount = 2_500_000i128;
        let salt = Bytes::from_slice(&env, &[11, 22, 33, 44]);

        let commitment1 = create_amount_commitment(&env, &owner, amount, salt.clone());
        let commitment2 = create_amount_commitment(&env, &owner, amount, salt);

        // Same inputs should produce identical commitments
        assert_eq!(commitment1, commitment2);
    }

    #[test]
    #[should_panic(expected = "Salt length exceeds maximum allowed")]
    fn test_salt_length_exceeds_max() {
        let env = setup();
        let owner = Address::generate(&env);
        let amount = 1_000i128;
        let oversized_salt = Bytes::from_slice(&env, &[42; 257]);

        // Should panic due to exceeding MAX_SALT_LENGTH
        let _ = create_amount_commitment(&env, &owner, amount, oversized_salt);
    }

    #[test]
    #[should_panic(expected = "Amount must be non-negative")]
    fn test_negative_amount() {
        let env = setup();
        let owner = Address::generate(&env);
        let amount = -1i128;
        let salt = Bytes::from_slice(&env, &[1, 2, 3]);

        // Should panic due to negative amount
        let _ = create_amount_commitment(&env, &owner, amount, salt);
    }
}
