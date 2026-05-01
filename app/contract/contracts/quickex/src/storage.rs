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
// TTL Policy Struct and Per-Record Policies
// -----------------------------------------------------------------------------

/// TTL policy for a record type.
pub struct TtlPolicy {
    /// Minimum remaining TTL (in ledgers) before extension is triggered.
    pub threshold: u32,
    /// TTL to set/extend to (in ledgers) when extension is triggered.
    pub ttl: u32,
}

/// Record types for TTL policy selection.
pub enum RecordType {
    Escrow,
    StealthEscrow,
    EscrowIdMap,
    FeeConfig,
    #[allow(dead_code)]
    Nonce,
    // Add more as needed
}

/// Returns the TTL policy for a given record type.
pub fn get_ttl_policy(record_type: RecordType) -> TtlPolicy {
    match record_type {
        RecordType::Escrow => TtlPolicy {
            threshold: LEDGER_THRESHOLD,
            ttl: SIX_MONTHS_IN_LEDGERS,
        },
        RecordType::StealthEscrow => TtlPolicy {
            threshold: LEDGER_THRESHOLD,
            ttl: SIX_MONTHS_IN_LEDGERS,
        },
        RecordType::EscrowIdMap => TtlPolicy {
            threshold: LEDGER_THRESHOLD,
            ttl: SIX_MONTHS_IN_LEDGERS,
        },
        RecordType::FeeConfig => TtlPolicy {
            threshold: LEDGER_THRESHOLD,
            ttl: SIX_MONTHS_IN_LEDGERS,
        },
        RecordType::Nonce => TtlPolicy {
            threshold: LEDGER_THRESHOLD,
            ttl: SIX_MONTHS_IN_LEDGERS,
        },
    }
}

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
    /// Emergency mode (singleton, immutable once set true).
    EmergencyMode,
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
    /// Oracle fee configuration for dynamic USD-based fees.
    OracleFeeConfig,
    /// Registered hook contract addresses.
    HookRegistry,
    /// Reentrancy guard to prevent callback-based reentry during hook execution.
    ReentrancyGuard,
    /// Boolean privacy flag per account.
    PrivacyEnabled(Address),
    /// Maps a deterministic 32-byte `escrow_id` (see [`crate::escrow_id`])
    /// to the commitment key of the escrow it identifies. Enables
    /// idempotent deduplication of identical creation requests.
    EscrowIdMap(BytesN<32>),
    /// Roles assigned to an address.
    UserRole(Address),
    /// Per-asset fee override keyed by token address (Fee Router v2).
    PerAssetFee(Address),
    /// Current active fee collector rotation index (Fee Router v2, singleton).
    FeeCollectorIndex,
    /// Fee collector address at a given rotation index (Fee Router v2).
    FeeCollector(u32),
}

// -----------------------------------------------------------------------------
// Emergency Mode helpers (module scope)
// -----------------------------------------------------------------------------
/// Set emergency mode. Once set to true, cannot be reverted.
pub fn set_emergency_mode(env: &Env) {
    let key = DataKey::EmergencyMode;
    let already_set: bool = env.storage().persistent().get(&key).unwrap_or(false);
    if !already_set {
        env.storage().persistent().set(&key, &true);
    }
    // If already set, do nothing (immutable)
}

/// Get emergency mode state.
pub fn is_emergency_mode(env: &Env) -> bool {
    let key = DataKey::EmergencyMode;
    env.storage().persistent().get(&key).unwrap_or(false)
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
    set_or_extend_ttl(env, &key, RecordType::Escrow);
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
    let result = env.storage().persistent().get(&key);
    if result.is_some() {
        set_or_extend_ttl(env, &key, RecordType::Escrow);
    }
    result
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

// -----------------------------------------------------------------------------
// TTL Helper
// -----------------------------------------------------------------------------

/// Set or extend TTL for a storage key based on record type policy.
pub fn set_or_extend_ttl(env: &Env, key: &DataKey, record_type: RecordType) {
    let policy = get_ttl_policy(record_type);
    env.storage()
        .persistent()
        .extend_ttl(key, policy.threshold, policy.ttl);
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
    let key = DataKey::FeeConfig;
    let result = env.storage().persistent().get(&key);
    if result.is_some() {
        set_or_extend_ttl(env, &key, RecordType::FeeConfig);
    }
    result.unwrap_or(FeeConfig { fee_bps: 0 })
}

pub fn set_fee_config(env: &Env, config: &FeeConfig) {
    let key = DataKey::FeeConfig;
    env.storage().persistent().set(&key, config);
    set_or_extend_ttl(env, &key, RecordType::FeeConfig);
}

pub fn get_platform_wallet(env: &Env) -> Option<Address> {
    env.storage().persistent().get(&DataKey::PlatformWallet)
}

pub fn set_platform_wallet(env: &Env, wallet: &Address) {
    env.storage()
        .persistent()
        .set(&DataKey::PlatformWallet, wallet);
}

pub fn get_oracle_fee_config(env: &Env) -> Option<crate::types::OracleFeeConfig> {
    env.storage().persistent().get(&DataKey::OracleFeeConfig)
}

pub fn set_oracle_fee_config(env: &Env, config: &crate::types::OracleFeeConfig) {
    env.storage()
        .persistent()
        .set(&DataKey::OracleFeeConfig, config);
}

pub fn get_registered_hooks(env: &Env) -> Vec<Address> {
    env.storage()
        .persistent()
        .get(&DataKey::HookRegistry)
        .unwrap_or(Vec::new(env))
}

pub fn set_registered_hooks(env: &Env, hooks: &Vec<Address>) {
    env.storage()
        .persistent()
        .set(&DataKey::HookRegistry, hooks);
}

pub fn get_reentrancy_guard(env: &Env) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::ReentrancyGuard)
        .unwrap_or(false)
}

pub fn set_reentrancy_guard(env: &Env, value: &bool) {
    env.storage()
        .persistent()
        .set(&DataKey::ReentrancyGuard, value);
}

// -----------------------------------------------------------------------------
// Stealth helpers
// -----------------------------------------------------------------------------

pub fn get_stealth_escrow(env: &Env, stealth_address: &BytesN<32>) -> Option<StealthEscrowEntry> {
    let key = DataKey::StealthEscrow(stealth_address.clone());
    let result = env.storage().persistent().get(&key);
    if result.is_some() {
        set_or_extend_ttl(env, &key, RecordType::StealthEscrow);
    }
    result
}

pub fn put_stealth_escrow(env: &Env, stealth_address: &BytesN<32>, entry: &StealthEscrowEntry) {
    let key = DataKey::StealthEscrow(stealth_address.clone());
    env.storage().persistent().set(&key, entry);
    set_or_extend_ttl(env, &key, RecordType::StealthEscrow);
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

// -----------------------------------------------------------------------------
// Fee Router v2 helpers (Issue #305)
// -----------------------------------------------------------------------------

/// Get per-asset fee config for `token`.
pub fn get_per_asset_fee(env: &Env, token: &Address) -> Option<crate::types::PerAssetFeeConfig> {
    let key = DataKey::PerAssetFee(token.clone());
    env.storage().persistent().get(&key)
}

/// Set per-asset fee config for `token`.
pub fn set_per_asset_fee(env: &Env, token: &Address, config: &crate::types::PerAssetFeeConfig) {
    let key = DataKey::PerAssetFee(token.clone());
    env.storage().persistent().set(&key, config);
}

/// Get current fee collector rotation index (default 0).
pub fn get_fee_collector_index(env: &Env) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::FeeCollectorIndex)
        .unwrap_or(0)
}

/// Set current fee collector rotation index.
pub fn set_fee_collector_index(env: &Env, index: u32) {
    env.storage()
        .persistent()
        .set(&DataKey::FeeCollectorIndex, &index);
}

/// Get fee collector address at a specific rotation index.
pub fn get_fee_collector_at(env: &Env, index: u32) -> Option<Address> {
    env.storage()
        .persistent()
        .get(&DataKey::FeeCollector(index))
}

/// Set fee collector address at a specific rotation index.
pub fn set_fee_collector_at(env: &Env, index: u32, collector: &Address) {
    env.storage()
        .persistent()
        .set(&DataKey::FeeCollector(index), collector);
}

// -----------------------------------------------------------------------------
// Escrow-id map helpers (Issue #304)
// -----------------------------------------------------------------------------

/// Look up the 32-byte commitment associated with a deterministic `escrow_id`.
pub fn get_escrow_id_mapping(env: &Env, escrow_id: &BytesN<32>) -> Option<BytesN<32>> {
    let key = DataKey::EscrowIdMap(escrow_id.clone());
    let result = env.storage().persistent().get(&key);
    if result.is_some() {
        set_or_extend_ttl(env, &key, RecordType::EscrowIdMap);
    }
    result
}

/// Record the mapping `escrow_id → commitment` so future identical creates
/// can be recognized and deduplicated.
pub fn put_escrow_id_mapping(env: &Env, escrow_id: &BytesN<32>, commitment: &BytesN<32>) {
    let key = DataKey::EscrowIdMap(escrow_id.clone());
    env.storage().persistent().set(&key, commitment);
    set_or_extend_ttl(env, &key, RecordType::EscrowIdMap);
}
