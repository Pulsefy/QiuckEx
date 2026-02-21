//! Types used in the QuickEx storage layer and contract logic.
//!
//! See [`crate::storage`] for the storage schema and key layout.

use soroban_sdk::{contracttype, Address};

/// Escrow entry status.
///
/// Tracks the lifecycle of a deposited commitment:
///
/// ```text
/// [*] --> Pending  : deposit()
/// Pending --> Spent    : withdraw(proof)  [current_time < expires_at]
/// Pending --> Refunded : refund(owner)    [current_time >= expires_at]
/// ```
///
/// - `Pending`:  Funds are escrowed, awaiting withdrawal or refund.
/// - `Spent`:    Withdrawal completed successfully. Terminal state.
/// - `Refunded`: Owner reclaimed funds after timeout. Terminal state.
#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EscrowStatus {
    Pending,
    Spent,
    /// Kept for backwards-compat with any existing on-chain data; semantically
    /// equivalent to an escrow that has passed expiry but not yet been refunded.
    Expired,
    Refunded,
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
    /// Owner who deposited and may refund after expiry.
    pub owner: Address,
    /// Current status (Pending, Spent, Refunded, Expired).
    pub status: EscrowStatus,
    /// Ledger timestamp when the escrow was created.
    pub created_at: u64,
    /// Ledger timestamp after which withdrawal is blocked and refund is enabled.
    /// A value of `0` means the escrow never expires (no timeout).
    pub expires_at: u64,
}
