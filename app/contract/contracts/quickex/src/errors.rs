use soroban_sdk::contracterror;

/// Canonical contract error codes.
///
/// Code bands:
/// - 100-199: validation failures
/// - 200-299: auth/admin failures
/// - 300-399: state, escrow, and commitment violations
/// - 900-999: internal/unexpected conditions
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum QuickexError {
    // Validation failures (100-199)
    InvalidAmount = 100,
    InvalidSalt = 101,
    InvalidPrivacyLevel = 102,
    // Auth/admin failures (200-299)
    Unauthorized = 200,
    AlreadyInitialized = 201,
    // State, escrow, and commitment violations (300-399)
    ContractPaused = 300,
    PrivacyAlreadySet = 301,
    CommitmentNotFound = 302,
    CommitmentAlreadyExists = 303,
    AlreadySpent = 304,
    InvalidCommitment = 305,
    CommitmentMismatch = 306,
    /// Escrow has passed its expiry; withdrawal is no longer possible.
    EscrowExpired = 307,
    /// Escrow has not yet expired; refund is not yet available.
    EscrowNotExpired = 308,
    /// Caller is not the original owner of the escrow.
    InvalidOwner = 309,
    /// No arbiter assigned to the escrow; dispute cannot be raised.
    NoArbiter = 310,
    /// Escrow is not in the required state for this operation.
    InvalidDisputeState = 311,
    /// Caller is not the assigned arbiter.
    NotArbiter = 312,
    /// The requested operation is paused via granular pause flags.
    OperationPaused = 313,
    // Stealth address errors (400-499)
    /// Derived stealth address does not match the provided one.
    StealthAddressMismatch = 400,
    /// A stealth escrow already exists for this stealth address.
    StealthAddressAlreadyUsed = 401,
    /// No stealth escrow found for the given stealth address.
    StealthEscrowNotFound = 402,
    // Internal/unexpected conditions (900-999)
    InternalError = 900,
}
