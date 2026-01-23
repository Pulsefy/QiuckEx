//! # Privacy Toggle Module
//!
//! Storage helpers and public methods for privacy toggle functionality.
//! Provides owner-only access control and event emission for privacy state changes.

use soroban_sdk::{contract, contractimpl, Env, Symbol, Address, symbol_short};
use crate::errors::Error;
use crate::events::EventPublisher;

/// Storage key for privacy state
const PRIVACY_KEY: Symbol = symbol_short!("privacy");

/// Privacy storage utilities
pub struct PrivacyStorage;

impl PrivacyStorage {
    /// Get the privacy state for an owner
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The account to query
    ///
    /// # Returns
    /// * `bool` - Current privacy state (false if not set)
    pub fn get_privacy_state(env: &Env, owner: &Address) -> bool {
        env.storage()
            .persistent()
            .get(&(PRIVACY_KEY, owner))
            .unwrap_or(false)
    }

    /// Set the privacy state for an owner (internal function)
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The account to update
    /// * `enabled` - The new privacy state
    pub fn set_privacy_state(env: &Env, owner: &Address, enabled: bool) {
        env.storage()
            .persistent()
            .set(&(PRIVACY_KEY, owner), &enabled);
    }
}

/// Public privacy methods
pub struct PrivacyContract;

#[contractimpl]
impl PrivacyContract {
    /// Set privacy mode for the calling owner
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The account that must authenticate this call
    /// * `enabled` - Whether to enable (true) or disable (false) privacy
    ///
    /// # Returns
    /// * `Result<(), Error>` - Success or specific error
    pub fn set_privacy(env: Env, owner: Address, enabled: bool) -> Result<(), Error> {
        // Require authentication from the owner
        owner.require_auth();

        // Store the new privacy state
        PrivacyStorage::set_privacy_state(&env, &owner, enabled);

        // Emit privacy toggled event
        EventPublisher::privacy_toggled(&env, owner, enabled);

        Ok(())
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
        PrivacyStorage::get_privacy_state(&env, &owner)
    }
}