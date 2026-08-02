//! # Signature Replay Protection & Nonce Registry (Domain Separation v2)
//!
//! Provides replay protection for any signature-based flow by enforcing:
//!
//! 1. **Per-(signer, action) nonce uniqueness** — each `(signer, nonce, action)`
//!    tuple can only be consumed once. Replaying the same nonce for the same
//!    action fails with [`QuickexError::NonceAlreadyUsed`].
//!
//! 2. **Expiry window** — the signed message carries a `valid_until` ledger
//!    timestamp. Submitting after that timestamp fails with
//!    [`QuickexError::SignatureExpired`].
//!
//! 3. **Domain separation v2** — the canonical payload that callers sign
//!    includes the contract address, network passphrase, **and action type**,
//!    so a signature produced for one method / contract / network cannot be
//!    replayed on another.
//!
//! ## Canonical Signed Payload Envelope (v2)
//!
//! Off-chain signers MUST construct the payload as:
//!
//! ```text
//! payload = concat(
//!     DOMAIN_TAG,                       // 28 bytes: "QUICKEX::SIGNED_PAYLOAD::v2"
//!     be32(len(contract_id_xdr)),       // 4 bytes
//!     contract_id_xdr,                  // variable (currently 52 bytes for Address)
//!     be32(len(network_passphrase)),    // 4 bytes
//!     network_passphrase_bytes,         // variable
//!     be32(len(action_type)),           // 4 bytes
//!     action_type_bytes,                // variable (e.g. "WITHDRAW")
//!     be64(nonce),                      // 8 bytes
//!     be64(valid_until),                // 8 bytes
//! )
//! signed_hash = SHA256(payload)
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! // Off-chain: build payload per the spec above, sign signed_hash with ed25519.
//!
//! // On-chain, call before processing the signed action:
//! nonce::verify_and_consume(
//!     &env,
//!     &signer,
//!     nonce,
//!     valid_until,
//!     ActionType::Withdraw,
//! )?;
//! ```
//!
//! ## Storage
//!
//! Consumed nonces are stored under [`NonceKey::Used`]`(signer, nonce, action)`
//! in **persistent** storage with a 6-month TTL. This prevents the registry
//! from growing unboundedly while still covering any realistic replay window.
//!
//! ## Migration (v1 → v2)
//!
//! - The old [`NonceKey::UsedV1`]`(signer, nonce)` key format is retained for
//!   backward-compatible reads during the transition period.
//! - The legacy [`domain_prefix_v1`] helper is still exported for test fixtures
//!   that may contain v1 signatures.
//! - New code MUST use [`build_canonical_payload`] and [`verify_and_consume`]
//!   with an explicit [`ActionType`].

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env};

use crate::errors::QuickexError;
use crate::storage::{LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS};

// ---------------------------------------------------------------------------
// Domain separation constants
// ---------------------------------------------------------------------------

/// Domain separation tag for v2 signed payloads.
///
/// Bump the version suffix if the canonical payload encoding ever changes
/// to guarantee that old and new signatures cannot collide.
pub const SIGNED_PAYLOAD_DOMAIN_TAG: &[u8] = b"QUICKEX::SIGNED_PAYLOAD::v2";

// ---------------------------------------------------------------------------
// Action type — method-level domain separation
// ---------------------------------------------------------------------------

/// Identifies which contract method a signature is bound to.
///
/// Each variant corresponds to a unique action tag, preventing a signature
/// produced for one method from being accepted by another.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ActionType {
    Withdraw,
    Refund,
    Dispute,
    ResolveDispute,
    VoteForDispute,
    ResolveDisputeMultiSig,
    Deposit,
    DepositWithCommitment,
    DepositPartial,
    PartialPayment,
    StealthDeposit,
    StealthWithdraw,
    SetPrivacy,
    Upgrade,
}

impl ActionType {
    /// Returns the byte-encoded action tag used in the canonical payload.
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            ActionType::Withdraw => b"WITHDRAW",
            ActionType::Refund => b"REFUND",
            ActionType::Dispute => b"DISPUTE",
            ActionType::ResolveDispute => b"RESOLVE_DISPUTE",
            ActionType::VoteForDispute => b"VOTE_FOR_DISPUTE",
            ActionType::ResolveDisputeMultiSig => b"RESOLVE_DISPUTE_MULTI_SIG",
            ActionType::Deposit => b"DEPOSIT",
            ActionType::DepositWithCommitment => b"DEPOSIT_WITH_COMMITMENT",
            ActionType::DepositPartial => b"DEPOSIT_PARTIAL",
            ActionType::PartialPayment => b"PARTIAL_PAYMENT",
            ActionType::StealthDeposit => b"STEALTH_DEPOSIT",
            ActionType::StealthWithdraw => b"STEALTH_WITHDRAW",
            ActionType::SetPrivacy => b"SET_PRIVACY",
            ActionType::Upgrade => b"UPGRADE",
        }
    }
}

// ---------------------------------------------------------------------------
// Storage key
// ---------------------------------------------------------------------------

/// Storage key for a consumed nonce.
///
/// Stored as `(signer_address, nonce_value, action_type) → true` in
/// persistent storage.
///
/// # Migration
///
/// [`UsedV1`] retains the legacy `(signer, nonce)` key layout so that any
/// nonces consumed before the v2 upgrade are still recognised.  All new
/// writes use [`Used`].
#[contracttype]
#[derive(Clone)]
pub enum NonceKey {
    /// Marks that `signer` has consumed `nonce` for `action` (v2 layout).
    Used(Address, u64, ActionType),
    /// Marks that `signer` has consumed `nonce` (legacy v1 layout).
    UsedV1(Address, u64),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify that `nonce` has not been used by `signer` for `action` and that
/// the current ledger timestamp is strictly before `valid_until`, then mark
/// the nonce as consumed.
///
/// # Errors
///
/// | Error | Condition |
/// |-------|-----------|
/// | [`QuickexError::NonceAlreadyUsed`] | `(signer, nonce, action)` already consumed |
/// | [`QuickexError::SignatureExpired`] | `env.ledger().timestamp() >= valid_until` |
pub fn verify_and_consume(
    env: &Env,
    signer: &Address,
    nonce: u64,
    valid_until: u64,
    action: ActionType,
) -> Result<(), QuickexError> {
    if env.ledger().timestamp() >= valid_until {
        return Err(QuickexError::SignatureExpired);
    }

    let key = NonceKey::Used(signer.clone(), nonce, action);
    if env.storage().persistent().has(&key) {
        return Err(QuickexError::NonceAlreadyUsed);
    }

    env.storage().persistent().set(&key, &true);
    env.storage()
        .persistent()
        .extend_ttl(&key, LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS);

    Ok(())
}

/// Returns `true` if `(signer, nonce, action)` has already been consumed.
///
/// Useful for off-chain pre-flight checks.
pub fn is_nonce_used(env: &Env, signer: &Address, nonce: u64, action: ActionType) -> bool {
    let key = NonceKey::Used(signer.clone(), nonce, action);
    env.storage().persistent().has(&key)
}

// ---------------------------------------------------------------------------
// Domain-separation helpers
// ---------------------------------------------------------------------------

/// Build the canonical v2 signed payload envelope.
///
/// Returns the full byte payload that off-chain signers MUST hash with SHA256
/// and sign with their ed25519 key.  The returned [`Bytes`] contains:
///
/// ```text
/// DOMAIN_TAG || be32(len(contract_id)) || contract_id_xdr
///     || be32(len(network)) || network_passphrase
///     || be32(len(action)) || action_bytes
///     || be64(nonce) || be64(valid_until)
/// ```
///
/// Callers may append additional application-specific data after `valid_until`
/// before hashing.
pub fn build_canonical_payload(
    env: &Env,
    action: ActionType,
    nonce: u64,
    valid_until: u64,
) -> Bytes {
    use soroban_sdk::xdr::ToXdr;

    let mut payload = Bytes::new(env);

    // 1 — Domain tag.
    payload.append(&Bytes::from_slice(env, SIGNED_PAYLOAD_DOMAIN_TAG));

    // 2 — Contract ID (length-prefixed XDR).
    let contract_xdr = env.current_contract_address().to_xdr(env);
    append_len_prefixed(env, &mut payload, &contract_xdr);

    // 3 — Network passphrase (length-prefixed).
    let passphrase = env.ledger().network_id();
    let passphrase_bytes: Bytes = passphrase.into();
    append_len_prefixed(env, &mut payload, &passphrase_bytes);

    // 4 — Action type (length-prefixed).
    let action_bytes = action.as_bytes();
    append_len_prefixed(env, &mut payload, &Bytes::from_slice(env, action_bytes));

    // 5 — Nonce as big-endian u64.
    payload.append(&Bytes::from_array(env, &nonce.to_be_bytes()));

    // 6 — Valid-until as big-endian u64.
    payload.append(&Bytes::from_array(env, &valid_until.to_be_bytes()));

    payload
}

/// Convenience: return the SHA256 hash of [`build_canonical_payload`].
///
/// This is the exact value the off-chain signer signs.  Off-chain code
/// should mirror this function exactly.
pub fn hash_canonical_payload(
    env: &Env,
    action: ActionType,
    nonce: u64,
    valid_until: u64,
) -> BytesN<32> {
    let payload = build_canonical_payload(env, action, nonce, valid_until);
    env.crypto().sha256(&payload).into()
}

/// Legacy v1 domain prefix (contract_id || network_passphrase).
///
/// Provided for migration compatibility.  New code MUST use
/// [`build_canonical_payload`] instead.
pub fn domain_prefix_v1(env: &Env) -> Bytes {
    use soroban_sdk::xdr::ToXdr;

    let contract_bytes = env.current_contract_address().to_xdr(env);
    let passphrase: Bytes = env.ledger().network_id().into();

    let mut prefix = Bytes::new(env);
    prefix.append(&contract_bytes);
    prefix.append(&passphrase);
    prefix
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Append `field` to `payload` with a 4-byte big-endian length prefix.
///
/// The prefix makes field boundaries unambiguous, so two distinct tuples
/// cannot produce the same serialized payload.
fn append_len_prefixed(env: &Env, payload: &mut Bytes, field: &Bytes) {
    let len = field.len();
    payload.append(&Bytes::from_array(env, &len.to_be_bytes()));
    payload.append(field);
}
