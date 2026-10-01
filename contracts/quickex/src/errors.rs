//! Error definitions for the Quickex contract.
//!
//! # Soroban `contracterror` case cap
//!
//! Soroban's `#[contracterror]` spec format encodes each variant as a `u32`
//! case and the generated XDR spec only supports **50 cases** (0..=49).
//! `QuickexError` currently sits at 49 variants — one below that hard cap —
//! so any new variant would break the generated contract spec.
//!
//! ## Variant budget
//!
//! * Hard cap: 50 cases (Soroban `contracterror` spec format).
//! * Soft cap: 48 cases — enforced at compile time by `VARIANT_COUNT` below.
//!   Reaching the soft cap fails the build so headroom is reclaimed *before*
//!   the hard cap is hit.
//!
//! ## Reclaiming headroom (audit)
//!
//! The following variants are candidates for consolidation into a single
//! generic variant plus an `ErrorDetail` companion value (event/return data),
//! rather than one dedicated variant per failure mode:
//!
//! * `InvalidAmount` / `InvalidFee` / `InvalidDeadline` / `InvalidRecipient`
//!   → `InvalidParameter(ErrorDetail)`.
//! * `Unauthorized` / `NotOwner` / `NotAdmin` → `Unauthorized(ErrorDetail)`.
//! * `AlreadyInitialized` / `NotInitialized` → `InvalidState(ErrorDetail)`.
//!
//! ## Strategy before the cap is hit
//!
//! New failure modes MUST NOT add a dedicated `QuickexError` variant. Instead
//! they should reuse an existing generic variant and carry the specifics in an
//! `ErrorDetail` companion value (emitted as an event or returned alongside the
//! error). This keeps the enum stable while still surfacing precise diagnostics.
//!
//! ## Governance cross-reference
//!
//! `.kiro/specs/governance-model-v1/requirements.md` Requirement 11 specifies
//! error codes 502-511 (10 new variants). Those cannot fit until headroom is
//! reclaimed per the plan above; see that document for the explicit constraint.

use soroban_sdk::contracterror;

/// Number of variants currently defined in [`QuickexError`].
///
/// Kept in sync manually; the compile-time assertion below fails the build if
/// this reaches the soft cap of 48, giving advance warning before Soroban's
/// hard 50-case `contracterror` limit.
pub const VARIANT_COUNT: u32 = 49;

/// Soft cap: fail the build once the variant count reaches this value.
pub const VARIANT_SOFT_CAP: u32 = 48;

/// Hard cap imposed by Soroban's `contracterror` spec format.
pub const VARIANT_HARD_CAP: u32 = 50;

// Compile-time guard: fails the build if the variant count reaches or exceeds
// the soft cap, warning maintainers before the hard 50-case limit is hit.
const _: () = assert!(VARIANT_COUNT < VARIANT_SOFT_CAP);

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum QuickexError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    NotOwner = 4,
    NotAdmin = 5,
    InvalidAmount = 6,
    InvalidFee = 7,
    InvalidDeadline = 8,
    InvalidRecipient = 9,
    InsufficientBalance = 10,
    EscrowNotFound = 11,
    EscrowAlreadyExists = 12,
    EscrowExpired = 13,
    EscrowNotExpired = 14,
    EscrowAlreadyReleased = 15,
    EscrowAlreadyRefunded = 16,
    EscrowNotFunded = 17,
    InvalidEscrowState = 18,
    InvalidToken = 19,
    TokenTransferFailed = 20,
    TokenMintFailed = 21,
    TokenBurnFailed = 22,
    ArithmeticOverflow = 23,
    DivisionByZero = 24,
    InvalidSignature = 25,
    SignatureExpired = 26,
    NonceAlreadyUsed = 27,
    InvalidNonce = 28,
    InvalidChainId = 29,
    InvalidContractId = 30,
    InvalidVersion = 31,
    UpgradeNotAuthorized = 32,
    UpgradeFailed = 33,
    Paused = 34,
    NotPaused = 35,
    InvalidPauseState = 36,
    FeeTooHigh = 37,
    FeeTooLow = 38,
    InvalidFeeRecipient = 39,
    InvalidFeeToken = 40,
    InvalidFeeAmount = 41,
    InvalidFeeBps = 42,
    InvalidFeeConfig = 43,
    InvalidDisputeState = 44,
    DisputeNotFound = 45,
    DisputeAlreadyResolved = 46,
    InvalidResolution = 47,
    InvalidArbitrator = 48,
    InvalidEvidence = 49,
}
