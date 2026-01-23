//! # Event Types and Publishers
//!
//! Event definitions and publishing utilities for the QuickSilver contract.
//! Enables on-chain event emission for privacy state changes.

use soroban_sdk::{contractevent, Env, Address};

/// Event data structure for privacy toggle operations
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyToggled {
    /// The account that toggled privacy
    pub owner: Address,
    /// The new privacy state (true = enabled, false = disabled)
    pub enabled: bool,
    /// Timestamp when the toggle occurred
    pub timestamp: u64,
}

/// Event publishing utilities
pub struct EventPublisher;

impl EventPublisher {
    /// Publish a privacy toggled event
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The account that toggled privacy
    /// * `enabled` - The new privacy state
    pub fn privacy_toggled(env: &Env, owner: Address, enabled: bool) {
        // Create and automatically publish the event via #[contractevent] macro
        PrivacyToggled {
            owner: owner.clone(),
            enabled,
            timestamp: env.ledger().timestamp(),
        };

        soroban_sdk::log!(env, "Privacy toggled for {}: {}", owner, enabled);
    }
}