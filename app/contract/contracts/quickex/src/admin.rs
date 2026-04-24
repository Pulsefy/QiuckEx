use crate::errors::QuickexError;
use crate::events::{publish_admin_changed, publish_contract_migrated, publish_contract_paused};
use crate::storage;
use crate::types::FeeConfig; // Added this import for FeeConfig
use soroban_sdk::{Address, Env};

/// Initialize the contract with an admin address.
///
/// This is a one-time operation; subsequent calls fail with [`AlreadyInitialized`].
/// The initial admin is allowed to pause/unpause, transfer admin, and upgrade.
pub fn initialize(env: &Env, admin: Address) -> Result<(), QuickexError> {
    if has_admin(env) {
        return Err(QuickexError::AlreadyInitialized);
    }

    // Seed admin and paused flags in persistent storage.
    storage::set_admin(env, &admin);
    storage::set_paused(env, false);
    storage::set_contract_version(env, storage::CURRENT_CONTRACT_VERSION);

    Ok(())
}

/// Check if admin has been initialized.
pub fn has_admin(env: &Env) -> bool {
    storage::get_admin(env).is_some()
}

/// Get the current admin address.
///
/// Returns `None` if the contract has not been initialised.
pub fn get_admin(env: &Env) -> Option<Address> {
    storage::get_admin(env)
}

/// Require that the caller is the admin (with auth).
///
/// - Fails with [`Unauthorized`] if no admin is set.
/// - Fails with [`Unauthorized`] if `caller` ≠ stored admin.
pub fn require_admin(env: &Env, caller: &Address) -> Result<(), QuickexError> {
    caller.require_auth();

    match storage::get_admin(env) {
        Some(admin) if admin == *caller => Ok(()),
        _ => Err(QuickexError::Unauthorized),
    }
}

/// Set a new admin address (**admin only**).
///
/// Emits an `AdminChanged` event for indexers.
pub fn set_admin(env: &Env, caller: Address, new_admin: Address) -> Result<(), QuickexError> {
    require_admin(env, &caller)?;

    // Safe to unwrap: `require_admin` guarantees an admin is set.
    let old_admin = storage::get_admin(env).unwrap();
    storage::set_admin(env, &new_admin);

    publish_admin_changed(env, old_admin, new_admin);

    Ok(())
}

/// Set the paused state (**admin only**).
///
/// Emits a `ContractPaused` event whenever the flag changes.
pub fn set_paused(env: &Env, caller: Address, new_state: bool) -> Result<(), QuickexError> {
    require_admin(env, &caller)?;

    storage::set_paused(env, new_state);

    publish_contract_paused(env, caller, new_state);

    Ok(())
}

/// Check if the contract is paused.
pub fn is_paused(env: &Env) -> bool {
    storage::is_paused(env)
}

pub fn get_version(env: &Env) -> u32 {
    storage::get_contract_version(env).unwrap_or(storage::LEGACY_CONTRACT_VERSION)
}

pub fn migrate(env: &Env, caller: &Address) -> Result<u32, QuickexError> {
    require_admin(env, caller)?;

    let from_version = get_version(env);
    if from_version > storage::CURRENT_CONTRACT_VERSION {
        return Err(QuickexError::InvalidContractVersion);
    }

    let mut version = from_version;
    while version < storage::CURRENT_CONTRACT_VERSION {
        version = match version {
            storage::LEGACY_CONTRACT_VERSION => migrate_legacy_to_v1(env),
            _ => return Err(QuickexError::InvalidContractVersion),
        };
    }

    if version != from_version {
        publish_contract_migrated(env, caller, from_version, version);
    }

    Ok(version)
}

fn migrate_legacy_to_v1(env: &Env) -> u32 {
    storage::set_contract_version(env, storage::CURRENT_CONTRACT_VERSION);
    storage::CURRENT_CONTRACT_VERSION
}

/// Require that the contract is not paused.
///
/// This helper should be called at the start of operations that are blocked when paused.
#[allow(dead_code)]
pub fn require_not_paused(env: &Env) -> Result<(), QuickexError> {
    if is_paused(env) {
        return Err(QuickexError::ContractPaused);
    }
    Ok(())
}

pub fn set_pause_flags(
    env: &Env,
    caller: &Address,
    flags_to_enable: u64,
    flags_to_disable: u64,
) -> Result<(), QuickexError> {
    require_admin(env, caller)?;

    storage::set_pause_flags(env, caller, flags_to_enable, flags_to_disable);

    Ok(())
}

/// Set fee configuration (**admin only**).
pub fn set_fee_config(env: &Env, caller: &Address, config: FeeConfig) -> Result<(), QuickexError> {
    require_admin(env, caller)?;
    storage::set_fee_config(env, &config);
    crate::events::publish_fee_config_changed(env, config.fee_bps);
    Ok(())
}

/// Set platform wallet address (**admin only**).
pub fn set_platform_wallet(
    env: &Env,
    caller: &Address,
    wallet: Address,
) -> Result<(), QuickexError> {
    require_admin(env, caller)?;
    storage::set_platform_wallet(env, &wallet);
    crate::events::publish_platform_wallet_changed(env, wallet);
    Ok(())
}
