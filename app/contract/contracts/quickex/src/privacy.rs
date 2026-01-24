use crate::errors::QuickexError;
use crate::events::publish_privacy_toggled;
use soroban_sdk::{Address, Env, Symbol};

pub fn set_privacy(env: &Env, owner: Address, enabled: bool) -> Result<(), QuickexError> {
    owner.require_auth();

    let key = Symbol::new(env, "privacy_enabled");
    env.storage()
        .persistent()
        .set(&(key, owner.clone()), &enabled);

    let timestamp = env.ledger().timestamp();
    publish_privacy_toggled(env, owner, enabled, timestamp);

    Ok(())
}

pub fn get_privacy(env: &Env, owner: Address) -> bool {
    let key = Symbol::new(env, "privacy_enabled");
    env.storage()
        .persistent()
        .get(&(key, owner))
        .unwrap_or(false)
}
