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

mod admin;
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

    /// Initialize the contract with an admin address
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `admin` - The admin address to set
    ///
    /// # Returns
    /// * `Result<(), QuickexError>` - Ok if successful, Error if already initialized
    pub fn initialize(env: Env, admin: Address) -> Result<(), QuickexError> {
        admin::initialize(&env, admin)
    }

    /// Set the paused state of the contract (Admin only)
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `caller` - The caller address (must be admin)
    /// * `new_state` - True to pause, False to unpause
    ///
    /// # Returns
    /// * `Result<(), QuickexError>` - Ok if successful, Error if unauthorized or other issue
    pub fn set_paused(env: Env, caller: Address, new_state: bool) -> Result<(), QuickexError> {
        admin::set_paused(&env, caller, new_state)
    }

    /// Transfer admin rights to a new address (Admin only)
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `caller` - The caller address (must be admin)
    /// * `new_admin` - The new admin address
    ///
    /// # Returns
    /// * `Result<(), QuickexError>` - Ok if successful, Error if unauthorized or other issue
    pub fn set_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), QuickexError> {
        admin::set_admin(&env, caller, new_admin)
    }

    /// Check if the contract is currently paused
    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    /// * `bool` - True if paused, False otherwise
    pub fn is_paused(env: Env) -> bool {
        admin::is_paused(&env)
    }

    /// Get the current admin address
    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    /// * `Option<Address>` - The admin address if set, None otherwise
    pub fn get_admin(env: Env) -> Option<Address> {
        admin::get_admin(&env)
    }
}

mod test;
