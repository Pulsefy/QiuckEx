//! # QuickEx Privacy Contract
//!
//! Soroban contract implementing X-Ray privacy features for QuickEx.
//! Provides privacy controls and escrow functionality for on-chain operations.
//!
//! ## Overview
//! This contract serves as the foundation for privacy-preserving operations
//! in the QuickEx ecosystem, enabling selective visibility and secure escrow.

#![no_std]

use soroban_sdk::{Address, Bytes, BytesN, Env, Map, Symbol, contract, contractimpl};

mod commitment;
mod errors;
mod events;
mod privacy;

use errors::QuickexError;

/// Main contract structure
#[contract]
pub struct QuickexContract;

/// Privacy-related methods
#[contractimpl]
impl QuickexContract {
    /// Enable or disable privacy for an account
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The account address to configure
    /// * `enabled` - True to enable privacy, False to disable
    ///
    /// # Returns
    /// * `Result<(), QuickexError>` - Ok if successful, Error otherwise
    pub fn set_privacy(env: Env, owner: Address, enabled: bool) -> Result<(), QuickexError> {
        privacy::set_privacy(&env, owner, enabled)
    }

    /// Check the current privacy status of an account
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The account address to query
    ///
    /// # Returns
    /// * `bool` - Current privacy status (true = enabled)
    pub fn get_privacy(env: Env, owner: Address) -> bool {
        privacy::get_privacy(&env, owner)
    }

    /// Create a commitment for a hidden amount
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The owner of the funds
    /// * `amount` - The amount to commit
    /// * `salt` - Random salt for privacy
    ///
    /// # Returns
    /// * `Result<BytesN<32>, QuickexError>` - The commitment hash
    pub fn create_amount_commitment(
        env: Env,
        owner: Address,
        amount: i128,
        salt: Bytes,
    ) -> Result<BytesN<32>, QuickexError> {
        commitment::create_amount_commitment(&env, owner, amount, salt)
    }

    /// Verify a commitment matches the provided values
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `commitment` - The commitment hash to verify
    /// * `owner` - The owner of the funds
    /// * `amount` - The amount to verify
    /// * `salt` - The salt used for the commitment
    ///
    /// # Returns
    /// * `bool` - True if valid
    pub fn verify_amount_commitment(
        env: Env,
        commitment: BytesN<32>,
        owner: Address,
        amount: i128,
        salt: Bytes,
    ) -> bool {
        commitment::verify_amount_commitment(&env, commitment, owner, amount, salt)
    }

    /// Placeholder for future escrow functionality
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `from` - Sender address
    /// * `to` - Recipient address
    /// * `amount` - Amount to escrow
    ///
    /// # Returns
    /// * `u64` - Escrow ID
    pub fn create_escrow(env: Env, from: Address, to: Address, _amount: u64) -> u64 {
        // Generate unique escrow ID using a counter
        let counter_key = Symbol::new(&env, "escrow_counter");
        let mut count: u64 = env.storage().persistent().get(&counter_key).unwrap_or(0);
        count += 1;
        env.storage().persistent().set(&counter_key, &count);

        let escrow_id = count;

        // Store escrow details
        let escrow_key = Symbol::new(&env, "escrow");
        let mut escrow_details = Map::<Symbol, Address>::new(&env);
        escrow_details.set(Symbol::new(&env, "from"), from);
        escrow_details.set(Symbol::new(&env, "to"), to);

        env.storage()
            .persistent()
            .set(&(escrow_key, escrow_id), &escrow_details);

        escrow_id
    }

    /// Simple health check function
    ///
    /// # Returns
    /// * `bool` - Always returns true to indicate contract is operational
    pub fn health_check() -> bool {
        true
    }

    /// Create an amount commitment for X-Ray privacy.
    ///
    /// Generates a deterministic SHA256 hash of the owner address, amount, and salt.
    /// This is a placeholder function without real zero-knowledge guarantees;
    /// future implementation will use actual ZK proofs.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The owner's address (for domain separation)
    /// * `amount` - The amount to commit to (must be non-negative)
    /// * `salt` - Random salt bytes for uniqueness (max 256 bytes)
    ///
    /// # Returns
    /// * `Bytes` - 32-byte SHA256 commitment hash
    ///
    /// # Panics
    /// * If amount is negative
    /// * If salt length exceeds 256 bytes
    pub fn create_amount_commitment(env: Env, owner: Address, amount: i128, salt: Bytes) -> Bytes {
        commitment::create_amount_commitment(&env, &owner, amount, salt)
    }

    /// Verify an amount commitment against claimed values.
    ///
    /// Recomputes the commitment from the provided amount and salt,
    /// returning true only if the recomputed hash matches the given commitment.
    /// Returns false for any tampering (modified amount, salt, or owner).
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `commitment` - The commitment bytes to verify (should be 32 bytes)
    /// * `owner` - The claimed owner address
    /// * `amount` - The claimed amount value
    /// * `salt` - The claimed salt bytes
    ///
    /// # Returns
    /// * `bool` - True if commitment is valid; false if tampered or mismatched
    pub fn verify_amount_commitment(
        env: Env,
        commitment: Bytes,
        owner: Address,
        amount: i128,
        salt: Bytes,
    ) -> bool {
        commitment::verify_amount_commitment(&env, &commitment, &owner, amount, salt)
    }
}

#[cfg(test)]
mod test;
