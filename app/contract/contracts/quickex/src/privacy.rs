use crate::errors::QuickexError;
use crate::events::publish_privacy_toggled;
use crate::storage::PRIVACY_ENABLED_KEY;
use soroban_sdk::{Address, Env, Symbol};

/// Enable or disable privacy for an account.
///
/// Reads the current state first and returns [`QuickexError::PrivacyAlreadySet`]
/// if the requested value matches the current value. Otherwise persists the new
/// state and publishes a [`crate::events::publish_privacy_toggled`] event.
pub fn set_privacy(env: &Env, owner: Address, enabled: bool) -> Result<(), QuickexError> {
    owner.require_auth();

    let key = Symbol::new(env, PRIVACY_ENABLED_KEY);
    let current: bool = env
        .storage()
        .persistent()
        .get(&(key.clone(), owner.clone()))
        .unwrap_or(false);

    if current == enabled {
        return Err(QuickexError::PrivacyAlreadySet);
    }

    env.storage()
        .persistent()
        .set(&(key, owner.clone()), &enabled);

    let timestamp = env.ledger().timestamp();
    publish_privacy_toggled(env, owner, enabled, timestamp);
    Ok(())
}

/// Return the current boolean privacy state for an account.
///
/// Defaults to `false` if never set.
pub fn get_privacy(env: &Env, owner: Address) -> bool {
    let key = Symbol::new(env, PRIVACY_ENABLED_KEY);
    env.storage()
        .persistent()
        .get(&(key, owner))
        .unwrap_or(false)
}
