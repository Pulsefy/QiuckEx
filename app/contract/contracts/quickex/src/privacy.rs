//! Canonical privacy state (Issue #862 / SC-W8-01).
//!
//! `contracts/quickex` historically exposed two independent privacy APIs that
//! could disagree about the same account: a numeric level (`enable_privacy` /
//! `privacy_status`) and a boolean flag (`set_privacy` / `get_privacy`). The
//! boolean flag is the one actually consulted by contract logic elsewhere
//! (e.g. the privacy-aware escrow view), so it is chosen here as the single
//! authoritative representation, stored under [`DataKey::PrivacyEnabled`].
//!
//! `enable_privacy` / `privacy_status` are kept as thin shims that read and
//! write through the exact same functions as `set_privacy` / `get_privacy`
//! (`0` = disabled, `1` = enabled), so the two call styles can never observe
//! contradictory state. Legacy data written before this change (either the
//! pre-typed-key boolean, or the deprecated numeric level) is transparently
//! migrated: reads fall back to it when the canonical key is unset, and any
//! write through this module clears it so the account converges permanently
//! onto the canonical key.
use crate::errors::QuickexError;
use crate::events::publish_privacy_toggled;
use crate::storage::{self, DataKey, PRIVACY_ENABLED_KEY};
use soroban_sdk::{Address, Env, Symbol, Vec};

fn legacy_privacy_key(env: &Env, owner: &Address) -> (Symbol, Address) {
    (Symbol::new(env, PRIVACY_ENABLED_KEY), owner.clone())
}

fn typed_privacy_key(owner: &Address) -> DataKey {
    DataKey::PrivacyEnabled(owner.clone())
}

/// Resolve the current privacy flag for an account, falling back through
/// every legacy representation in priority order. Never mutates storage.
fn read_privacy_flag(env: &Env, owner: &Address) -> bool {
    let typed_key = typed_privacy_key(owner);
    if let Some(enabled) = env.storage().persistent().get(&typed_key) {
        return enabled;
    }

    if let Some(enabled) = env
        .storage()
        .persistent()
        .get(&legacy_privacy_key(env, owner))
    {
        return enabled;
    }

    storage::get_privacy_level(env, owner)
        .map(|level| level > 0)
        .unwrap_or(false)
}

/// Whether the account has ever touched any privacy representation
/// (canonical, legacy boolean, or deprecated numeric level).
fn has_any_privacy_state(env: &Env, owner: &Address) -> bool {
    env.storage().persistent().has(&typed_privacy_key(owner))
        || env
            .storage()
            .persistent()
            .has(&legacy_privacy_key(env, owner))
        || storage::get_privacy_level(env, owner).is_some()
}

/// Write the canonical flag and migrate away every legacy representation for
/// this account, so a later read can never fall back to stale data.
fn write_canonical(env: &Env, owner: &Address, enabled: bool) {
    env.storage()
        .persistent()
        .set(&typed_privacy_key(owner), &enabled);

    let legacy_key = legacy_privacy_key(env, owner);
    if env.storage().persistent().has(&legacy_key) {
        env.storage().persistent().remove(&legacy_key);
    }
    storage::clear_privacy_level(env, owner);
}

/// Enable or disable privacy for an account (canonical entrypoint).
///
/// Reads the current state first and returns [`QuickexError::PrivacyAlreadySet`]
/// if the requested value matches the current value. Otherwise persists the new
/// state and publishes a [`crate::events::publish_privacy_toggled`] event.
pub fn set_privacy(env: &Env, owner: Address, enabled: bool) -> Result<(), QuickexError> {
    owner.require_auth();

    let current = read_privacy_flag(env, &owner);
    if current == enabled {
        return Err(QuickexError::PrivacyAlreadySet);
    }

    write_canonical(env, &owner, enabled);
    publish_privacy_toggled(env, owner, enabled);
    Ok(())
}

/// Return the current boolean privacy state for an account.
///
/// Defaults to `false` if never set.
pub fn get_privacy(env: &Env, owner: Address) -> bool {
    read_privacy_flag(env, &owner)
}

/// Deprecated numeric-level shim over the canonical boolean state.
///
/// `privacy_level` must be `0` (disabled) or `1` (enabled); any other value
/// returns [`QuickexError::InvalidPrivacyLevel`]. Delegates entirely to
/// [`set_privacy`], so it shares its auth requirement, idempotency error, and
/// event — the two entrypoints can never disagree. Also appends the
/// requested level to the account's audit history for callers still relying
/// on [`privacy_history`].
pub fn enable_privacy(
    env: &Env,
    account: Address,
    privacy_level: u32,
) -> Result<bool, QuickexError> {
    let enabled = match privacy_level {
        0 => false,
        1 => true,
        _ => return Err(QuickexError::InvalidPrivacyLevel),
    };

    set_privacy(env, account.clone(), enabled)?;
    storage::add_privacy_history(env, &account, privacy_level);
    Ok(enabled)
}

/// Deprecated numeric-level shim over the canonical boolean state.
///
/// Returns `None` if the account has never touched any privacy entrypoint,
/// otherwise projects the canonical flag back into `{0, 1}` so it can never
/// disagree with [`get_privacy`].
pub fn privacy_status(env: &Env, account: Address) -> Option<u32> {
    if !has_any_privacy_state(env, &account) {
        return None;
    }
    Some(read_privacy_flag(env, &account) as u32)
}

/// Deprecated append-only audit log of levels requested via [`enable_privacy`].
pub fn privacy_history(env: &Env, account: Address) -> Vec<u32> {
    storage::get_privacy_history(env, &account)
}
