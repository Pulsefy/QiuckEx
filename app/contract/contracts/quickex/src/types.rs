use soroban_sdk::{contracttype, Address};

/// Escrow entry status
#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EscrowStatus {
    Pending,
    Spent,
    Expired,
}

/// Escrow entry structure
#[contracttype]
#[derive(Clone)]
pub struct EscrowEntry {
    pub token: Address,
    pub amount: i128,
    pub owner: Address,
    pub status: EscrowStatus,
    pub created_at: u64,
}
