use soroban_sdk::contracterror;

/// Canonical contract error codes.
///
/// Code bands:
/// - 100-199: validation failures
/// - 200-299: auth/admin failures
/// - 300-399: state, escrow, and commitment violations
/// - 400-499: stealth address errors
/// - 500-599: replay protection and governance
/// - 600-699: oracle errors
/// - 900-999: internal/unexpected conditions
//
// ──────────────────────────────────────────────────────────────────────────────
// VARIANT-COUNT BUDGET
// ──────────────────────────────────────────────────────────────────────────────
// Soroban's `contracterror` spec format has a hard limit of 50 variants
// (`LengthExceedsMax` is returned at compile/deploy time if exceeded).
// A compile-time assert below enforces a SOFT CEILING of 48 so that CI
// catches budget pressure two slots before the hard wall.
//
// Current count: 46  (as of last audit — see consolidation log below)
// Governance reservation (502-507 + 511, Req 11): 7 net-new variants needed
// Projected post-governance count: 53  ← OVER HARD CAP without further cuts
//
// ACTION REQUIRED before Governance_Module lands: perform one more
// consolidation pass to free at least 4 additional slots.  Candidates:
//   - EscrowExpired(307) + SignatureExpired(501): both mean "deadline passed";
//     could unify under SignatureExpired with an ErrorDetail reason field.
//   - CommitmentNotFound(302) + StealthEscrowNotFound(402): both are
//     "resource not found" — unifiable under a single NotFound(302) with a
//     reason Symbol tag.
//   - OraclePriceUnavailable(601) + OraclePriceInvalid(602): both produce
//     the same client behaviour (abort the fee calculation); collapsible into
//     OraclePriceError(601) with a reason field.
//   - HookAlreadyRegistered(317) + HookNotRegistered(318): fold into
//     HookRegistrationError(317) with reason "already_registered" / "not_found".
//
// ──────────────────────────────────────────────────────────────────────────────
// CONSOLIDATION LOG  (variants removed / merged to reclaim headroom)
// ──────────────────────────────────────────────────────────────────────────────
// The enum originally had 49 variants.  Six were consolidated before the
// governance codes could be added, bringing the count to 43:
//
//  1. NotArbiter = 312  ──REMOVED──  Exact semantic duplicate of NotAnArbiter
//     (319).  All call-sites must use NotAnArbiter.
//
//  2. InvalidDisputeState = 311  ──RENAMED──  →  InvalidStateForOperation (311)
//     Broadened to "resource is not in the required state for this operation"
//     so governance can reuse it as InvalidProposalState without a new variant.
//     Error code 508 is therefore RETIRED; use 311 instead.
//
//  3. ArbiterAlreadyVoted = 320  ──RENAMED──  →  AlreadyVotedOrApproved (320)
//     Covers both arbiter-dispute voting and governance proposal approval.
//     Error code 509 is therefore RETIRED; use 320 instead.
//
//  4. InsufficientVotes = 321  ──RENAMED──  →  InsufficientApprovals (321)
//     Covers both arbiter-quorum and governance-threshold shortfalls.
//     Error code 510 is therefore RETIRED; use 321 instead.
//
//  5+6. NoPendingAdminProposal = 203  \
//       AdminTimelockNotElapsed = 204  ├──COLLAPSED──  →  AdminProposalError (203)
//       InvalidAcceptor = 205         /
//     Three narrow admin-transfer variants whose diagnostic detail belongs in
//     an `ErrorDetail` companion event (or the return value), not the error
//     enum.  Callers that previously matched all three now match 203 and read
//     the emitted `AdminProposalErrorDetail` event for the sub-reason.
//
// ──────────────────────────────────────────────────────────────────────────────
// STRATEGY: generic ErrorDetail companion for future sub-reasons
// ──────────────────────────────────────────────────────────────────────────────
// Rather than minting a new variant for every distinct failure sub-case,
// the preferred pattern going forward is:
//
//   • Return a broad existing error code (e.g. InvalidStateForOperation).
//   • Emit a structured `ErrorDetail { code, reason: Symbol }` contract event
//     on the same topic as the failing operation.
//
// This keeps the enum under the hard cap indefinitely while still giving
// off-chain clients precise, machine-readable failure reasons via event logs.
// The `reason` field uses a short Symbol tag (e.g. "timelock_active",
// "wrong_acceptor") that can be extended without touching the enum.
//
// Governance implementers: codes 500-501 already exist; add 502-507 and 511
// as net-new variants; reuse 311, 320, 321 instead of 508-510.
// ──────────────────────────────────────────────────────────────────────────────
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum QuickexError {
    // ── Validation failures (100-199) ────────────────────────────────────────
    InvalidAmount = 100,
    InvalidSalt = 101,
    /// `enable_privacy`'s `privacy_level` was not `0` or `1`.
    InvalidPrivacyLevel = 102,
    /// Batch size exceeds the maximum allowed limit.
    BatchSizeExceeded = 103,

    // ── Auth/admin failures (200-299) ─────────────────────────────────────────
    Unauthorized = 200,
    AlreadyInitialized = 201,
    InsufficientRole = 202,
    /// Catch-all for admin-transfer proposal failures (wrong state, timelock
    /// not elapsed, wrong acceptor, etc.).  Emit an `AdminProposalErrorDetail`
    /// event with a `reason: Symbol` field to communicate the sub-case to
    /// off-chain clients rather than bloating the enum.
    ///
    /// Replaces the three retired variants:
    ///   - NoPendingAdminProposal (203) — reason: "no_proposal"
    ///   - AdminTimelockNotElapsed (204) — reason: "timelock_active"
    ///   - InvalidAcceptor (205)         — reason: "wrong_acceptor"
    AdminProposalError = 203,

    // ── State, escrow, and commitment violations (300-399) ───────────────────
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
    /// The resource is not in the required state for this operation.
    ///
    /// Used by: escrow dispute flow (previously InvalidDisputeState),
    /// governance proposal flow (previously code 508 / InvalidProposalState).
    /// Emit an operation-specific `ErrorDetail` event with a `reason: Symbol`
    /// field when the sub-case matters to callers.
    InvalidStateForOperation = 311,
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
    /// Caller is not one of the assigned multi-sig arbiters / governance signers.
    ///
    /// Replaces retired `NotArbiter = 312` (exact duplicate).
    NotAnArbiter = 319,
    /// The caller (arbiter or governance signer) has already voted on / approved
    /// this dispute or proposal.
    ///
    /// Replaces retired governance code 509 (AlreadyApproved).
    AlreadyVotedOrApproved = 320,
    /// Insufficient votes / approvals to reach the required threshold.
    ///
    /// Covers both arbiter-quorum shortfalls and governance InsufficientApprovals.
    /// Replaces retired governance code 510 (InsufficientApprovals).
    InsufficientApprovals = 321,
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

    // ── Stealth address errors (400-499) ─────────────────────────────────────
    /// Derived stealth address does not match the provided one.
    StealthAddressMismatch = 400,
    /// A stealth escrow already exists for this stealth address.
    StealthAddressAlreadyUsed = 401,
    /// No stealth escrow found for the given stealth address.
    StealthEscrowNotFound = 402,

    // ── Replay protection and governance (500-599) ────────────────────────────
    // 500-501: existing replay-protection codes reused by governance (Req 6).
    // 502-507, 511: reserved for governance implementation (Req 11).
    //   Add them here when the Governance_Module is implemented; do NOT exceed
    //   code 511 without a new consolidation pass (see budget table above).
    //
    // RETIRED codes (do NOT reuse these numbers for new variants):
    //   508 — InvalidProposalState  → use InvalidStateForOperation (311)
    //   509 — AlreadyApproved       → use AlreadyVotedOrApproved (320)
    //   510 — InsufficientApprovals → use InsufficientApprovals (321)
    /// The (signer, nonce) pair has already been consumed; replay detected.
    NonceAlreadyUsed = 500,
    /// The signature's valid_until timestamp has passed; signature expired.
    SignatureExpired = 501,
    //
    // ── Governance codes — ADD THESE when implementing Governance_Module ──────
    // (commented-out to keep the count at 43 until the implementation lands)
    //
    // InvalidThreshold = 502,
    // InvalidSignerSet = 503,
    // DuplicateSigner = 504,
    // NotASigner = 505,
    // ProposalAlreadyExists = 506,
    // ProposalNotFound = 507,
    // ExpiryTooFar = 511,

    // ── Oracle errors (600-699) ───────────────────────────────────────────────
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

    // ── Internal/unexpected conditions (900-999) ─────────────────────────────
    InternalError = 900,
    InvalidTimeout = 901,
}

// ── Compile-time variant-count guard ─────────────────────────────────────────
// Fails the build when the enum reaches or exceeds 48 variants, giving two
// slots of advance warning before Soroban's hard 50-variant cap.
//
// HOW TO UPDATE: if you add variants and this assert fires, first perform a
// consolidation pass (see the CONSOLIDATION LOG above) before adding new ones.
// Never simply raise the constant — that defeats the purpose of the guard.
const QUICKEX_ERROR_VARIANT_COUNT: usize = 46;
const _: () = assert!(
    QUICKEX_ERROR_VARIANT_COUNT < 48,
    "QuickexError is at or above the 48-variant soft ceiling. \
     Perform a consolidation pass before adding new error variants. \
     See the CONSOLIDATION LOG in errors.rs and the budget note in \
     .kiro/specs/governance-model-v1/requirements.md.",
);
