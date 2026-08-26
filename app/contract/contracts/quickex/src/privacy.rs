use crate::errors::QuickexError;
use crate::events::publish_privacy_toggled;
use crate::storage::{add_privacy_history, DataKey, PRIVACY_ENABLED_KEY};
use soroban_sdk::{Address, Env, Symbol};

fn legacy_symbol_privacy_key(env: &Env, owner: &Address) -> (Symbol, Address) {
    (Symbol::new(env, PRIVACY_ENABLED_KEY), owner.clone())
}

fn deprecated_typed_privacy_key(owner: &Address) -> DataKey {
    DataKey::PrivacyEnabled(owner.clone())
}

/// Read the canonical privacy level for an account, performing lazy migration from deprecated storage keys.
///
/// **Canonical Representation**:
/// - `DataKey::PrivacyLevel(account) -> u32` is the single authoritative privacy state.
/// - Level `0` represents privacy disabled (off).
/// - Level `>0` represents privacy enabled (on), with level `1` as the default tier for boolean calls.
/// - Returns `None` if privacy has never been configured for the account.
pub fn get_privacy_level(env: &Env, account: &Address) -> Option<u32> {
    let canonical_key = DataKey::PrivacyLevel(account.clone());
    if let Some(level) = env.storage().persistent().get::<_, u32>(&canonical_key) {
        return Some(level);
    }

    // Lazy migration path for deprecated typed boolean key
    let typed_key = deprecated_typed_privacy_key(account);
    if let Some(enabled) = env.storage().persistent().get::<_, bool>(&typed_key) {
        let level = if enabled { 1u32 } else { 0u32 };
        env.storage().persistent().set(&canonical_key, &level);
        env.storage().persistent().remove(&typed_key);
        return Some(level);
    }

    // Lazy migration path for legacy Symbol-based key: (Symbol("privacy_enabled"), Address)
    let legacy_key = legacy_symbol_privacy_key(env, account);
    if let Some(enabled) = env.storage().persistent().get::<_, bool>(&legacy_key) {
        let level = if enabled { 1u32 } else { 0u32 };
        env.storage().persistent().set(&canonical_key, &level);
        env.storage().persistent().remove(&legacy_key);
        return Some(level);
    }

    None
}

/// Set the canonical privacy level for an account, cleaning up deprecated storage keys if present.
pub fn set_privacy_level(env: &Env, account: Address, level: u32) {
    let canonical_key = DataKey::PrivacyLevel(account.clone());
    env.storage().persistent().set(&canonical_key, &level);

    // Clean up deprecated keys if present
    let typed_key = deprecated_typed_privacy_key(&account);
    if env.storage().persistent().has(&typed_key) {
        env.storage().persistent().remove(&typed_key);
    }

    let legacy_key = legacy_symbol_privacy_key(env, &account);
    if env.storage().persistent().has(&legacy_key) {
        env.storage().persistent().remove(&legacy_key);
    }
}

/// Enable a numeric privacy level for an account (level-based API).
///
/// Sets the canonical privacy level and appends the new level to history.
pub fn enable_privacy(env: &Env, account: Address, privacy_level: u32) -> bool {
    set_privacy_level(env, account.clone(), privacy_level);
    add_privacy_history(env, &account, privacy_level);
    publish_privacy_toggled(env, account, privacy_level > 0);
    true
}

/// Return the numeric privacy level for an account.
pub fn privacy_status(env: &Env, account: Address) -> Option<u32> {
    get_privacy_level(env, &account)
}

/// Enable or disable boolean privacy for an account.
///
/// Reimplemented as a thin shim over the canonical numeric level representation.
/// Setting `enabled = true` maps to canonical privacy level `1`.
/// Setting `enabled = false` maps to canonical privacy level `0`.
/// Returns [`QuickexError::PrivacyAlreadySet`] if the requested boolean state matches current.
pub fn set_privacy(env: &Env, owner: Address, enabled: bool) -> Result<(), QuickexError> {
    owner.require_auth();

    let current = get_privacy(env, owner.clone());
    if current == enabled {
        return Err(QuickexError::PrivacyAlreadySet);
    }

    let target_level = if enabled { 1u32 } else { 0u32 };
    set_privacy_level(env, owner.clone(), target_level);
    add_privacy_history(env, &owner, target_level);
    publish_privacy_toggled(env, owner, enabled);
    Ok(())
}

/// Return the current boolean privacy state for an account.
///
/// Under the consolidated privacy model, privacy is enabled if and only if
/// the account's canonical privacy level is greater than 0.
pub fn get_privacy(env: &Env, owner: Address) -> bool {
    get_privacy_level(env, &owner).is_some_and( |level| level > 0)
}
