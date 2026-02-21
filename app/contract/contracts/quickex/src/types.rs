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

/// Privacy-aware view of an escrow entry.
///
/// Returned by [`QuickexContract::get_escrow_details`] instead of the raw
/// [`EscrowEntry`]. Sensitive fields (`amount`, `owner`) are set to `None`
/// when the escrow owner has privacy enabled and the caller is not the owner.
///
/// ## Field visibility
///
/// | Field        | Privacy off | Privacy on + caller is owner | Privacy on + caller is stranger |
/// |--------------|-------------|------------------------------|---------------------------------|
/// | `token`      | ✓           | ✓                            | ✓                               |
/// | `status`     | ✓           | ✓                            | ✓                               |
/// | `created_at` | ✓           | ✓                            | ✓                               |
/// | `expires_at` | ✓           | ✓                            | ✓                               |
/// | `amount`     | ✓           | ✓                            | `None`                          |
/// | `owner`      | ✓           | ✓                            | `None`                          |
#[contracttype]
#[derive(Clone)]
pub struct PrivacyAwareEscrowView {
    /// Token contract address (always visible).
    pub token: Address,
    /// Escrowed amount. `None` when privacy is enabled and caller is not the owner.
    pub amount: Option<i128>,
    /// Owner address. `None` when privacy is enabled and caller is not the owner.
    pub owner: Option<Address>,
    /// Current lifecycle status (always visible).
    pub status: EscrowStatus,
    /// Creation timestamp (always visible).
    pub created_at: u64,
    /// Expiry timestamp; `0` means no expiry (always visible).
    pub expires_at: u64,
}
