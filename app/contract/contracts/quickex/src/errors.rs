use soroban_sdk::contracterror;

/// Canonical contract error codes.
///
/// Code bands:
/// - 100-199: validation failures
/// - 200-299: auth/admin failures
/// - 300-399: state, escrow, and commitment violations
/// - 900-999: internal/unexpected conditions
// Capped at 50 cases by Soroban's spec format (`LengthExceedsMax` if
// exceeded); near that ceiling — prefer reusing a close variant over adding
// a new one. (Plain comment, not `///`: doc comments here are embedded in
// the on-chain contract spec and count toward the WASM size budget.)
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum QuickexError {
    // Validation failures (100-199)
    InvalidAmount = 100,
    InvalidSalt = 101,
    /// `enable_privacy`'s `privacy_level` was not `0` or `1`.
    InvalidPrivacyLevel = 102,
    /// Batch size exceeds the maximum allowed limit.
    BatchSizeExceeded = 103,
    // Auth/admin failures (200-299)
    Unauthorized = 200,
    AlreadyInitialized = 201,
    InsufficientRole = 202,
    /// No admin-transfer proposal is currently pending.
    NoPendingAdminProposal = 203,
    /// The proposal's timelock has not yet elapsed.
    AdminTimelockNotElapsed = 204,
    /// Caller does not match the address named in the pending proposal.
    InvalidAcceptor = 205,
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
    /// The stored contract version cannot be migrated by this release.
    InvalidContractVersion = 314,
    /// Payment amount exceeds the remaining amount due for the escrow.
    Overpayment = 315,
    /// Reentrant callback detected during hook invocation.
    ReentrancyDetected = 316,
    /// Hook contract is already registered.
    HookAlreadyRegistered = 317,
    /// Hook contract was not registered.
    HookNotRegistered = 318,
    /// Caller is not one of the assigned multi-sig arbiters.
    NotAnArbiter = 319,
    /// Arbiter has already voted on this dispute.
    ArbiterAlreadyVoted = 320,
    /// Insufficient arbiter votes to reach the threshold for resolution.
    InsufficientVotes = 321,
    /// Hook contract is not allowed.
    HookNotAllowed = 322,
    /// Escrow entry was not found in live storage; it may have been archived by
    /// the ledger after its TTL expired.  Call `restore_archived_escrow` once
    /// the entry has been restored on-chain, then retry the operation.
    EscrowArchived = 323,
    /// The requested TTL value violates the configured policy bounds
    /// (either below the minimum or above the maximum allowed ledgers).
    TtlOutOfBounds = 324,
    /// Dispute-quorum config (`quorum` or `vote_ttl_secs`) violates hard bounds.
    QuorumOutOfBounds = 325,
    // Stealth address errors (400-499)
    /// Derived stealth address does not match the provided one.
    StealthAddressMismatch = 400,
    /// A stealth escrow already exists for this stealth address.
    StealthAddressAlreadyUsed = 401,
    /// No stealth escrow found for the given stealth address.
    StealthEscrowNotFound = 402,
    // Oracle errors (600-699)
    /// Oracle price data exceeds the configured staleness threshold and was rejected.
    OracleStalePrice = 600,
    /// No oracle price has been cached yet; dynamic fee cannot be computed.
    OraclePriceUnavailable = 601,
    /// The cached oracle price is zero or negative, which is invalid.
    OraclePriceInvalid = 602,
    /// Fewer than the configured minimum number of fresh, non-outlier oracle
    /// sources are available; the aggregated price cannot be trusted
    /// (SC-W8-06). Fails closed rather than pricing on too few feeds.
    OracleInsufficientSources = 603,
    /// The oracle source address is already registered.
    OracleSourceAlreadyRegistered = 604,
    /// The oracle source address is not registered.
    OracleSourceNotRegistered = 605,
    // Internal/unexpected conditions (900-999)
    InternalError = 900,
    InvalidTimeout = 901,
    // Replay protection (500-599)
    /// The (signer, nonce) pair has already been consumed; replay detected.
    NonceAlreadyUsed = 500,
    /// The signature's valid_until timestamp has passed; signature expired.
    SignatureExpired = 501,
}
