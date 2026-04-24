use crate::errors::QuickexError;
use crate::events::{publish_admin_changed, publish_contract_migrated, publish_contract_paused};
use crate::storage;
use crate::types::{FeeConfig, Role};
use soroban_sdk::{Address, Env, Vec};

/// Initialize the contract with an admin address.
///
/// This is a one-time operation; subsequent calls fail with [`AlreadyInitialized`].
/// The initial admin is assigned the [`Role::Admin`] role.
pub fn initialize(env: &Env, admin: Address) -> Result<(), QuickexError> {
    if has_admin(env) {
        return Err(QuickexError::AlreadyInitialized);
    }

    // Set initial admin address (singleton for compatibility).
    storage::set_admin(env, &admin);
    storage::set_paused(env, false);
    storage::set_contract_version(env, storage::CURRENT_CONTRACT_VERSION);

    // Grant Admin role to the initial administrator.
    let mut roles = Vec::new(env);
    roles.push_back(Role::Admin);
    storage::set_roles(env, &admin, &roles);

    Ok(())
}

/// Check if admin has been initialized.
pub fn has_admin(env: &Env) -> bool {
    storage::get_admin(env).is_some()
}

/// Get the current primary admin address.
pub fn get_admin(env: &Env) -> Option<Address> {
    storage::get_admin(env)
}

/// Check if an address has a specific role.
pub fn has_role(env: &Env, address: &Address, role: Role) -> bool {
    let roles = storage::get_roles(env, address);
    roles.contains(role)
}

/// Require that the caller has at least one of the specified roles.
pub fn require_any_role(env: &Env, caller: &Address, roles: &[Role]) -> Result<(), QuickexError> {
    caller.require_auth();
    let user_roles = storage::get_roles(env, caller);
    for role in roles {
        if user_roles.contains(*role) {
            return Ok(());
        }
    }
    Err(QuickexError::InsufficientRole)
}

/// Require that the caller is an Admin.
pub fn require_admin(env: &Env, caller: &Address) -> Result<(), QuickexError> {
    require_any_role(env, caller, &[Role::Admin])
}

/// Grant a role to an address (**Admin only**).
pub fn grant_role(
    env: &Env,
    caller: Address,
    target: Address,
    role: Role,
) -> Result<(), QuickexError> {
    require_admin(env, &caller)?;

    let mut roles = storage::get_roles(env, &target);
    if !roles.contains(role) {
        roles.push_back(role);
        storage::set_roles(env, &target, &roles);
    }
    Ok(())
}

/// Revoke a role from an address (**Admin only**).
pub fn revoke_role(
    env: &Env,
    caller: Address,
    target: Address,
    role: Role,
) -> Result<(), QuickexError> {
    require_admin(env, &caller)?;

    let roles = storage::get_roles(env, &target);
    let mut new_roles = Vec::new(env);
    for r in roles {
        if r != role {
            new_roles.push_back(r);
        }
    }
    storage::set_roles(env, &target, &new_roles);
    Ok(())
}

/// Set a new primary admin address (**Admin only**).
pub fn set_admin(env: &Env, caller: Address, new_admin: Address) -> Result<(), QuickexError> {
    require_admin(env, &caller)?;

    let old_admin = storage::get_admin(env).unwrap();
    storage::set_admin(env, &new_admin);

    // Revoke Admin role from old admin.
    let roles = storage::get_roles(env, &old_admin);
    let mut new_roles = Vec::new(env);
    for r in roles {
        if r != Role::Admin {
            new_roles.push_back(r);
        }
    }
    storage::set_roles(env, &old_admin, &new_roles);

    // Grant Admin role to new admin if not already present.
    let mut roles = storage::get_roles(env, &new_admin);
    if !roles.contains(Role::Admin) {
        roles.push_back(Role::Admin);
        storage::set_roles(env, &new_admin, &roles);
    }

    publish_admin_changed(env, old_admin, new_admin);
    Ok(())
}

/// Set the paused state (**Admin or Operator only**).
pub fn set_paused(env: &Env, caller: Address, new_state: bool) -> Result<(), QuickexError> {
    require_any_role(env, &caller, &[Role::Admin, Role::Operator])?;

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
    let from_version = get_version(env);
    if from_version == storage::LEGACY_CONTRACT_VERSION {
        caller.require_auth();

        let admin = storage::get_admin(env).ok_or(QuickexError::Unauthorized)?;
        if admin != *caller {
            return Err(QuickexError::InsufficientRole);
        }

        // Legacy deployments may not have role assignments. Seed Admin role so
        // post-migration admin checks continue to work.
        let mut roles = storage::get_roles(env, caller);
        if !roles.contains(Role::Admin) {
            roles.push_back(Role::Admin);
            storage::set_roles(env, caller, &roles);
        }
    } else {
        require_admin(env, caller)?;
    }

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
#[allow(dead_code)]
pub fn require_not_paused(env: &Env) -> Result<(), QuickexError> {
    if is_paused(env) {
        return Err(QuickexError::ContractPaused);
    }
    Ok(())
}

/// Set granular pause flags (**Admin or Operator only**).
pub fn set_pause_flags(
    env: &Env,
    caller: &Address,
    flags_to_enable: u64,
    flags_to_disable: u64,
) -> Result<(), QuickexError> {
    require_any_role(env, caller, &[Role::Admin, Role::Operator])?;

    storage::set_pause_flags(env, caller, flags_to_enable, flags_to_disable);
    Ok(())
}

/// Set fee configuration (**Admin or Operator only**).
pub fn set_fee_config(env: &Env, caller: &Address, config: FeeConfig) -> Result<(), QuickexError> {
    require_any_role(env, caller, &[Role::Admin, Role::Operator])?;

    storage::set_fee_config(env, &config);
    crate::events::publish_fee_config_changed(env, config.fee_bps);
    Ok(())
}

/// Set platform wallet address (**Admin only**).
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
