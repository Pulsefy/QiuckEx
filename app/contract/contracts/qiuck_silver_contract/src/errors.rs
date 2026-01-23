//! # Error Types
//!
//! Centralized error definitions for the QuickSilver contract.
//! Provides typed errors for better error handling and debugging.

use soroban_sdk::{contracterror, Env};

/// Contract error types for QuickSilver privacy operations
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Unauthorized access attempt
    Unauthorized = 1,

    /// Invalid input parameter
    InvalidInput = 2,

    /// Storage operation failed
    StorageError = 3,
}

/// Error conversion utilities
impl Error {
    /// Convert error to a user-friendly string message
    pub fn to_string(&self, env: &Env) -> soroban_sdk::String {
        match self {
            Error::Unauthorized => soroban_sdk::String::from_str(env, "Unauthorized access"),
            Error::InvalidInput => soroban_sdk::String::from_str(env, "Invalid input parameter"),
            Error::StorageError => soroban_sdk::String::from_str(env, "Storage operation failed"),
        }
    }
}
