use crate::errors::QuickexError;
use crate::events::{publish_admin_changed, publish_contract_paused};
use soroban_sdk::{symbol_short, Address, Env, Symbol};

#[allow(dead_code)]
const ADMIN_KEY: Symbol = symbol_short!("ADMIN");
#[allow(dead_code)]
const PAUSED_KEY: Symbol = symbol_short!("PAUSED");

/// Initialize the contract with an admin address
#[allow(dead_code)]
pub fn initialize(env: &Env, admin: Address) -> Result<(), QuickexError> {
    if has_admin(env) {
        return Err(QuickexError::AlreadyInitialized);
    }

    env.storage().instance().set(&ADMIN_KEY, &admin);
    env.storage().instance().set(&PAUSED_KEY, &false);

    Ok(())
}

/// Check if admin has been initialized
#[allow(dead_code)]
pub fn has_admin(env: &Env) -> bool {
    env.storage().instance().has(&ADMIN_KEY)
}

/// Get the current admin address
#[allow(dead_code)]
pub fn get_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&ADMIN_KEY)
}

/// Require that the caller is the admin
#[allow(dead_code)]
pub fn require_admin(env: &Env, caller: &Address) -> Result<(), QuickexError> {
    caller.require_auth();

    match get_admin(env) {
        Some(admin) if admin == *caller => Ok(()),
        _ => Err(QuickexError::Unauthorized),
    }
}

/// Set a new admin address (Admin only)
#[allow(dead_code)]
pub fn set_admin(env: &Env, caller: Address, new_admin: Address) -> Result<(), QuickexError> {
    require_admin(env, &caller)?;

    let old_admin = get_admin(env).unwrap();
    env.storage().instance().set(&ADMIN_KEY, &new_admin);

    let timestamp = env.ledger().timestamp();
    publish_admin_changed(env, old_admin, new_admin, timestamp);

    Ok(())
}

/// Set the paused state (Admin only)
#[allow(dead_code)]
pub fn set_paused(env: &Env, caller: Address, new_state: bool) -> Result<(), QuickexError> {
    require_admin(env, &caller)?;

    env.storage().instance().set(&PAUSED_KEY, &new_state);

    let timestamp = env.ledger().timestamp();
    publish_contract_paused(env, caller, new_state, timestamp);

    Ok(())
}

/// Check if the contract is paused
pub fn is_paused(env: &Env) -> bool {
    env.storage().instance().get(&PAUSED_KEY).unwrap_or(false)
}

/// Require that the contract is not paused
/// This helper function should be called at the start of deposit/withdraw functions
#[allow(dead_code)]
pub fn require_not_paused(env: &Env) -> Result<(), QuickexError> {
    if is_paused(env) {
        return Err(QuickexError::ContractPaused);
    }
    Ok(())
}
