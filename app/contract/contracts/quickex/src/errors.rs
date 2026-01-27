use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum QuickexError {
    AlreadyInitialized = 1,
    Unauthorized = 2,
    PrivacyAlreadySet = 3,
    InvalidPrivacyLevel = 4,
    InvalidAmount = 5,
    InvalidSalt = 6,
    CommitmentMismatch = 7,
    CommitmentNotFound = 8,
    AlreadySpent = 9,
    InvalidCommitment = 10,
    ContractPaused = 11,
    CommitmentAlreadyExists = 12,
}
