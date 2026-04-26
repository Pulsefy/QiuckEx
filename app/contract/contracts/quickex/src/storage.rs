//! # QuickEx Storage Schema
//!
//! This module defines the persistent storage layout for the QuickEx contract.
//! All long-term data is stored via the [`DataKey`] enum, which centralises key
//! construction and ensures type-safe storage access.
//!
//! ## Key Layout
//!
//! | Key Variant            | Value Type     | Description |
//! |------------------------|----------------|-------------|
//! | [`Escrow`](DataKey::Escrow) | `EscrowEntry`  | Escrow entry keyed by commitment hash (32 bytes). One entry per unique deposit. |
//! | [`EscrowCounter`](DataKey::EscrowCounter) | `u64`       | Global monotonic counter for escrow creation. |
//! | [`ContractVersion`](DataKey::ContractVersion) | `u32` | Stored schema/version marker for upgrade migrations. |
//! | [`Admin`](DataKey::Admin) | `Address`     | Contract admin address. Set during initialisation, transferable by admin. |
//! | [`Paused`](DataKey::Paused) | `bool`       | Global pause flag. When true, critical operations may be blocked. |
//! | [`PrivacyLevel`](DataKey::PrivacyLevel) | `u32`  | Numeric privacy level per account (0 = off). Used by `enable_privacy`. |
//! | [`PrivacyHistory`](DataKey::PrivacyHistory) | `Vec<u32>` | Per-account history of privacy level changes (chronological). |
//!
//! ## Related Keys (legacy compatibility)
//!
//! | Key                    | Format                    | Value Type | Description |
//! |------------------------|---------------------------|------------|-------------|
//! | `privacy_enabled`      | `(Symbol, Address)`       | `bool`     | Legacy boolean privacy on/off key. Read as a fallback and migrated to [`DataKey::PrivacyEnabled`] on write. |
//!
//! ## Relations
//!
//! - **Escrow ↔ Commitment**: Each `Escrow(Bytes)` key is derived from a 32-byte commitment hash
//!   (`SHA256(owner || amount || salt)`). The stored [`EscrowEntry`] contains token, amount, owner,
//!   status, and created_at.
//! - **Admin ↔ Paused**: Admin can set the paused flag. Both are singleton keys.
//! - **PrivacyLevel ↔ PrivacyHistory**: Same account may have both; level is current, history is append-only.
//! - **PrivacyLevel / PrivacyHistory ↔ PrivacyEnabled**: Separate APIs; level-based vs boolean. Both persist per `Address`.
//!
//! ## Backwards Compatibility
//!
//! For future upgrades:
//! - **Do not** remove or change the discriminant of existing [`DataKey`] variants.
//! - **Add** new variants for new keys; they will not collide with existing ones.
//! - **Value layout**: Changing `EscrowEntry` fields may require migration logic; adding optional
//!   fields can be done carefully with defaults.

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, Vec};

use crate::types::{EscrowEntry, FeeConfig, Role, StealthEscrowEntry};

// -----------------------------------------------------------------------------
// Key constants (for keys not using DataKey)
// -----------------------------------------------------------------------------

/// Symbol string for the legacy boolean privacy-enabled flag.
/// Used as `(Symbol::new(env, PRIVACY_ENABLED_KEY), Address)` in persistent storage.
/// See [`crate::privacy`] module for fallback/migration behaviour.
pub const PRIVACY_ENABLED_KEY: &str = "privacy_enabled";

pub const LEGACY_CONTRACT_VERSION: u32 = 0;
pub const CURRENT_CONTRACT_VERSION: u32 = 1;

pub const LEDGER_THRESHOLD: u32 = 17280; // ~1 day
pub const SIX_MONTHS_IN_LEDGERS: u32 = 3110400; // ~185 days

/// Bitmask flags for granular operation pausing.
#[contracttype]
#[repr(u64)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PauseFlag {
    Deposit = 1,
    Withdrawal = 2,
    Refund = 4,
    DepositWithCommitment = 8,
    SetPrivacy = 16,
    CreateAmountCommitment = 32,
}

// -----------------------------------------------------------------------------
// DataKey enum – central key derivation
// -----------------------------------------------------------------------------

/// Storage keys for the contract.
///
/// All persistent storage access should go through the helpers in this module.
/// Each variant maps to a distinct namespace; the Soroban runtime serialises
/// the enum discriminant and payload into the actual storage key.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Escrow entry keyed by commitment hash (`Bytes`, typically 32 bytes).
    Escrow(Bytes),
    /// Global escrow counter (singleton).
    EscrowCounter,
    /// Current contract schema version (singleton).
    ContractVersion,
    /// Admin address (singleton).
    Admin,
    /// Paused state (singleton).
    Paused,
    /// Numeric privacy level per account.
    PrivacyLevel(Address),
    /// Privacy level change history per account.
    PrivacyHistory(Address),
    /// Stealth escrow entry keyed by the 32-byte stealth address (Privacy v2).
    StealthEscrow(BytesN<32>),
    /// Granular operation pause bitmask (singleton).
    PauseFlags,
    /// Fee configuration (singleton).
    FeeConfig,
    /// Platform wallet address for fee collection (singleton).
    PlatformWallet,
    /// Boolean privacy flag per account.
    PrivacyEnabled(Address),
    /// Maps a deterministic 32-byte `escrow_id` (see [`crate::escrow_id`])
    /// to the commitment key of the escrow it identifies. Enables
    /// idempotent deduplication of identical creation requests.
    EscrowIdMap(BytesN<32>),
    /// Roles assigned to an address.
    UserRole(Address),
}

// -----------------------------------------------------------------------------
// Escrow helpers
// -----------------------------------------------------------------------------

/// Put an escrow entry into storage.
///
/// **Contract**: Overwrites any existing entry for the same commitment.
/// The commitment should be the 32-byte `SHA256(owner || amount || salt)` hash.
pub fn put_escrow(env: &Env, commitment: &Bytes, entry: &EscrowEntry) {
    let key = DataKey::Escrow(commitment.clone());
    env.storage().persistent().set(&key, entry);
    // Extend TTL for 6 months if current TTL < 10 days
    env.storage()
        .persistent()
        .extend_ttl(&key, LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS);
}

/// Remove an escrow entry from storage and reclaim the storage deposit.
pub fn remove_escrow(env: &Env, commitment: &Bytes) {
    let key = DataKey::Escrow(commitment.clone());
    env.storage().persistent().remove(&key);
}

/// Get an escrow entry from storage.
///
/// **Contract**: Returns `None` if no escrow exists for the commitment.
pub fn get_escrow(env: &Env, commitment: &Bytes) -> Option<EscrowEntry> {
    let key = DataKey::Escrow(commitment.clone());
    env.storage().persistent().get(&key)
}

/// Check if an escrow entry exists in storage.
#[allow(dead_code)]
pub fn has_escrow(env: &Env, commitment: &Bytes) -> bool {
    let key = DataKey::Escrow(commitment.clone());
    env.storage().persistent().has(&key)
}

/// Get the next escrow counter value.
///
/// **Contract**: Returns 0 if never set. Counter is used for `create_escrow`.
#[allow(dead_code)]
pub fn get_escrow_counter(env: &Env) -> u64 {
    let key = DataKey::EscrowCounter;
    env.storage().persistent().get(&key).unwrap_or(0)
}

/// Increment and return the escrow counter.
///
/// **Contract**: Atomic increment. Initial value treated as 0.
pub fn increment_escrow_counter(env: &Env) -> u64 {
    let key = DataKey::EscrowCounter;
    let mut count: u64 = env.storage().persistent().get(&key).unwrap_or(0);
    count += 1;
    env.storage().persistent().set(&key, &count);
    count
}

pub fn get_contract_version(env: &Env) -> Option<u32> {
    env.storage().persistent().get(&DataKey::ContractVersion)
}

pub fn set_contract_version(env: &Env, version: u32) {
    env.storage()
        .persistent()
        .set(&DataKey::ContractVersion, &version);
}

// -----------------------------------------------------------------------------
// Admin helpers
// -----------------------------------------------------------------------------

/// Set admin address.
#[allow(dead_code)]
pub fn set_admin(env: &Env, admin: &Address) {
    let key = DataKey::Admin;
    env.storage().persistent().set(&key, admin);
}

/// Get admin address.
#[allow(dead_code)]
pub fn get_admin(env: &Env) -> Option<Address> {
    let key = DataKey::Admin;
    env.storage().persistent().get(&key)
}

/// Set paused state.
#[allow(dead_code)]
pub fn set_paused(env: &Env, paused: bool) {
    let key = DataKey::Paused;
    env.storage().persistent().set(&key, &paused);
}

/// Set pause flags (granular pause control – caller already verified by admin module).
pub fn set_pause_flags(env: &Env, _caller: &Address, flags_to_enable: u64, flags_to_disable: u64) {
    let key = DataKey::PauseFlags;
    let current: u64 = env.storage().persistent().get(&key).unwrap_or(0);
    let updated = (current | flags_to_enable) & !flags_to_disable;
    env.storage().persistent().set(&key, &updated);
}

/// Check whether a specific operation flag is paused.
pub fn is_feature_paused(env: &Env, flag: PauseFlag) -> bool {
    let key = DataKey::PauseFlags;
    let flags: u64 = env.storage().persistent().get(&key).unwrap_or(0);
    flags & (flag as u64) != 0
}

/// Get paused state.
#[allow(dead_code)]
pub fn is_paused(env: &Env) -> bool {
    let key = DataKey::Paused;
    env.storage().persistent().get(&key).unwrap_or(false)
}

// -----------------------------------------------------------------------------
// Privacy helpers (level-based API)
// -----------------------------------------------------------------------------

/// Set privacy level for an account.
pub fn set_privacy_level(env: &Env, account: &Address, level: u32) {
    let key = DataKey::PrivacyLevel(account.clone());
    env.storage().persistent().set(&key, &level);
}

/// Get privacy level for an account.
pub fn get_privacy_level(env: &Env, account: &Address) -> Option<u32> {
    let key = DataKey::PrivacyLevel(account.clone());
    env.storage().persistent().get(&key)
}

/// Add to privacy history for an account.
///
/// **Contract**: Pushes `level` to the front of the history (newest first).
/// History is unbounded; consider capping in future if needed.
pub fn add_privacy_history(env: &Env, account: &Address, level: u32) {
    let key = DataKey::PrivacyHistory(account.clone());
    let mut history: Vec<u32> = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env));
    history.push_front(level);
    env.storage().persistent().set(&key, &history);
}

/// Get privacy history for an account.
///
/// **Contract**: Returns empty vec if never set. Order is newest-first.
pub fn get_privacy_history(env: &Env, account: &Address) -> Vec<u32> {
    let key = DataKey::PrivacyHistory(account.clone());
    env.storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env))
}

// -----------------------------------------------------------------------------
// Fee & Wallet helpers
// -----------------------------------------------------------------------------

pub fn get_fee_config(env: &Env) -> FeeConfig {
    env.storage()
        .persistent()
        .get(&DataKey::FeeConfig)
        .unwrap_or(FeeConfig { fee_bps: 0 })
}

pub fn set_fee_config(env: &Env, config: &FeeConfig) {
    env.storage().persistent().set(&DataKey::FeeConfig, config);
}

pub fn get_platform_wallet(env: &Env) -> Option<Address> {
    env.storage().persistent().get(&DataKey::PlatformWallet)
}

pub fn set_platform_wallet(env: &Env, wallet: &Address) {
    env.storage()
        .persistent()
        .set(&DataKey::PlatformWallet, wallet);
}

// -----------------------------------------------------------------------------
// Stealth helpers
// -----------------------------------------------------------------------------

pub fn get_stealth_escrow(env: &Env, stealth_address: &BytesN<32>) -> Option<StealthEscrowEntry> {
    let key = DataKey::StealthEscrow(stealth_address.clone());
    env.storage().persistent().get(&key)
}

pub fn put_stealth_escrow(env: &Env, stealth_address: &BytesN<32>, entry: &StealthEscrowEntry) {
    let key = DataKey::StealthEscrow(stealth_address.clone());
    env.storage().persistent().set(&key, entry);
    env.storage()
        .persistent()
        .extend_ttl(&key, LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS);
}

// -----------------------------------------------------------------------------
// Role helpers
// -----------------------------------------------------------------------------

pub fn get_roles(env: &Env, address: &Address) -> Vec<Role> {
    let key = DataKey::UserRole(address.clone());
    env.storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env))
}

pub fn set_roles(env: &Env, address: &Address, roles: &Vec<Role>) {
    let key = DataKey::UserRole(address.clone());
    env.storage().persistent().set(&key, roles);
    env.storage()
        .persistent()
        .extend_ttl(&key, LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS);
}

// -----------------------------------------------------------------------------
// Escrow-id map helpers (Issue #304)
// -----------------------------------------------------------------------------

/// Look up the 32-byte commitment associated with a deterministic `escrow_id`.
pub fn get_escrow_id_mapping(env: &Env, escrow_id: &BytesN<32>) -> Option<BytesN<32>> {
    env.storage()
        .persistent()
        .get(&DataKey::EscrowIdMap(escrow_id.clone()))
}

/// Record the mapping `escrow_id → commitment` so future identical creates
/// can be recognized and deduplicated.
pub fn put_escrow_id_mapping(env: &Env, escrow_id: &BytesN<32>, commitment: &BytesN<32>) {
    let key = DataKey::EscrowIdMap(escrow_id.clone());
    env.storage().persistent().set(&key, commitment);
    env.storage()
        .persistent()
        .extend_ttl(&key, LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS);
}
