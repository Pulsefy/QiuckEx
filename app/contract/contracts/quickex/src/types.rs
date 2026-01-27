use soroban_sdk::{contracttype, Address, BytesN};

/// Escrow entry status
#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EscrowStatus {
    Pending,
    Spent,
}

/// Escrow entry structure
#[contracttype]
#[derive(Clone)]
pub struct EscrowEntry {
    pub commitment: BytesN<32>,
    pub token: Address,
    pub amount: i128,
    pub status: EscrowStatus,
    pub depositor: Address,
}
