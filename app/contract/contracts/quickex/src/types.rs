//! Types used in the QuickEx storage layer and contract logic.
//!
//! See [`crate::storage`] for the storage schema and key layout.

use soroban_sdk::{contracttype, Address};

/// Escrow entry status.
///
/// Tracks the lifecycle of a deposited commitment:
/// - `Pending`: Funds are escrowed, awaiting withdrawal.
/// - `Spent`: Withdrawal completed; entry kept for audit/state queries.
/// - `Expired`: No longer withdrawable (reserved for future expiration logic).
#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EscrowStatus {
    Pending,
    Spent,
    Expired,
}

/// Escrow entry structure.
///
/// Stored under [`DataKey::Escrow`](crate::storage::DataKey::Escrow)(commitment) in persistent storage.
/// Each entry corresponds to one deposit, keyed by the commitment hash
/// `SHA256(owner || amount || salt)`.
#[contracttype]
#[derive(Clone)]
pub struct EscrowEntry {
    /// Token contract address for the escrowed funds.
    pub token: Address,
    /// Amount in token base units.
    pub amount: i128,
    /// Owner who can withdraw via proof of ownership (salt + amount).
    pub owner: Address,
    /// Current status (Pending, Spent, Expired).
    pub status: EscrowStatus,
    /// Ledger timestamp when the escrow was created.
    pub created_at: u64,
}
