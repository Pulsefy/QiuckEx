//! # QuickSilver Privacy Contract
//!
//! Soroban contract implementing X-Ray privacy features for QuickEx.
//! Provides privacy controls, access control, event emission, and escrow functionality.
//!
//! ## Overview
//! This contract serves as the foundation for privacy-preserving operations
//! in the QuickEx ecosystem, enabling selective visibility, secure escrow,
//! and on-chain privacy state management.

#![no_std]

// Module declarations
mod errors;
mod events;
mod privacy;

// Re-exports for external usage
pub use errors::Error;
pub use events::{EventPublisher, PrivacyToggledEvent};
pub use privacy::{PrivacyContract, PrivacyStorage};

use soroban_sdk::{contract, contractimpl, Env, Symbol, Address, Vec, Map};

/// Main contract structure
#[contract]
pub struct QuickSilverContract;

/// Privacy toggle methods (new v0 implementation)
#[contractimpl]
impl QuickSilverContract {
    /// Set privacy mode for the calling owner
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The account that must authenticate this call
    /// * `enabled` - Whether to enable (true) or disable (false) privacy
    ///
    /// # Returns
    /// * `Result<(), Error>` - Success or specific error
    ///
    /// # Security
    /// Requires authentication from the owner account
    pub fn set_privacy(env: Env, owner: Address, enabled: bool) -> Result<(), Error> {
        PrivacyContract::set_privacy(env, owner, enabled)
    }

    /// Get the current privacy state for an account
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The account to query
    ///
    /// # Returns
    /// * `bool` - Current privacy state (false if not set)
    pub fn get_privacy(env: Env, owner: Address) -> bool {
        PrivacyContract::get_privacy(env, owner)
    }

    /// Legacy: Initialize privacy settings for an account
    /// NOTE: This method is deprecated, use set_privacy instead
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `account` - The account address to configure
    /// * `privacy_level` - Desired privacy level (0-3)
    ///
    /// # Returns
    /// * `bool` - True if privacy was successfully enabled
    pub fn enable_privacy(env: Env, account: Address, privacy_level: u32) -> bool {
        // Store privacy settings
        let key = Symbol::new(&env, "privacy_level");
        env.storage().persistent().set(&(key, account.clone()), &privacy_level);

        // Initialize privacy history
        let history_key = Symbol::new(&env, "privacy_history");
        let mut history: Vec<u32> = env.storage().persistent()
            .get(&(history_key.clone(), account.clone()))
            .unwrap_or(Vec::new(&env));

        history.push_front(privacy_level);
        env.storage().persistent().set(&(history_key, account), &history);

        true
    }

    /// Legacy: Check the current privacy status of an account
    /// NOTE: This method is deprecated, use get_privacy instead
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `account` - The account address to query
    ///
    /// # Returns
    /// * `Option<u32>` - Current privacy level if set, None otherwise
    pub fn privacy_status(env: Env, account: Address) -> Option<u32> {
        let key = Symbol::new(&env, "privacy_level");
        env.storage().persistent().get(&(key, account))
    }

    /// Get privacy history for an account
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `account` - The account address to query
    ///
    /// # Returns
    /// * `Vec<u32>` - History of privacy level changes
    pub fn privacy_history(env: Env, account: Address) -> Vec<u32> {
        let key = Symbol::new(&env, "privacy_history");
        env.storage().persistent()
            .get(&(key, account))
            .unwrap_or(Vec::new(&env))
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
        // Generate unique escrow ID
        let escrow_id = env.ledger().timestamp() as u64;

        // Store escrow details
        let escrow_key = Symbol::new(&env, "escrow");
        let mut escrow_details = Map::<Symbol, Address>::new(&env);
        escrow_details.set(Symbol::new(&env, "from"), from);
        escrow_details.set(Symbol::new(&env, "to"), to);

        env.storage().persistent().set(&(escrow_key, escrow_id), &escrow_details);

        escrow_id
    }

    /// Simple health check function
    ///
    /// # Returns
    /// * `bool` - Always returns true to indicate contract is operational
    pub fn health_check() -> bool {
        true
    }
}


#[cfg(test)]
mod test;