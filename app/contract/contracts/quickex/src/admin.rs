use crate::errors::QuickexError;
use crate::events::{publish_admin_changed, publish_contract_paused};
use crate::storage;
use soroban_sdk::{Address, Env};

/// Initialize the contract with an admin address.
///
/// This is a one-time operation; subsequent calls fail with [`AlreadyInitialized`].
/// The initial admin is allowed to pause/unpause, transfer admin, and upgrade.
#[allow(dead_code)]
pub fn initialize(env: &Env, admin: Address) -> Result<(), QuickexError> {
    if has_admin(env) {
        return Err(QuickexError::AlreadyInitialized);
    }

    // Seed admin and paused flags in persistent storage.
    storage::set_admin(env, &admin);
    storage::set_paused(env, false);

    Ok(())
}

/// Check if admin has been initialized.
#[allow(dead_code)]
pub fn has_admin(env: &Env) -> bool {
    storage::get_admin(env).is_some()
}

/// Get the current admin address.
///
/// Returns `None` if the contract has not been initialised.
#[allow(dead_code)]
pub fn get_admin(env: &Env) -> Option<Address> {
    storage::get_admin(env)
}

/// Require that the caller is the admin (with auth).
///
/// - Fails with [`Unauthorized`] if no admin is set.
/// - Fails with [`Unauthorized`] if `caller` ≠ stored admin.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
