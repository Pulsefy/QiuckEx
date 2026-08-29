//! Versioned migration step registry (SC-W8-10 / Issue #871).
//!
//! Before this module, `migrate()` walked a raw `match` inside a `while`
//! loop, and each step returned a bare `u32` with no way to signal failure
//! partway through a multi-version upgrade. That made "migrating across
//! more than one version, or re-running a migration" undefined behaviour
//! for stored data, per the issue this closes.
//!
//! ## Design
//!
//! - [`step_for`] is the registry: one explicit, ordered entry per schema
//!   version, each a `fn(&Env) -> Result<(), QuickexError>`. Extend it by
//!   adding a new arm when a new schema version is introduced — never
//!   remove or reorder existing arms (see the module doc on
//!   [`crate::storage`] for the same rule applied to `DataKey`).
//! - [`run`] (via [`run_with`]) applies every step from `from_version` up
//!   to `to_version` **in order**, one version at a time, stopping at the
//!   first failure. Re-running with `from_version == to_version` is a
//!   no-op: the loop condition never executes a step.
//! - Failure handling is deliberately simple: propagate the `Err` and stop.
//!   Soroban's contract-invocation model rolls back *every* storage write
//!   made during a failed invocation — including writes already made by
//!   earlier steps in the same `run` call — so there is no need (and no
//!   safe way) to hand-roll a rollback here. `admin::migrate` relies on
//!   this by propagating the error with `?` rather than swallowing it.
//!   See `upgrade_test.rs`'s
//!   `upgrade_harness_failed_migration_leaves_version_at_prior_value` for
//!   the end-to-end proof, and the `tests` module below for direct
//!   coverage of the ordering/short-circuit logic in isolation.
//!
//! ## Testing note
//!
//! [`run_with`] takes the step registry as a parameter so the tests below
//! can exercise multi-step chains and mid-chain failures against a fake
//! registry, independent of how many real schema versions QuickEx has
//! shipped so far (currently just the one legacy→v1 step). [`run`] is the
//! thin production entry point that always uses the real [`step_for`].

use crate::{errors::QuickexError, storage};
use soroban_sdk::Env;

/// One ordered migration step: brings storage from its version up to
/// exactly one version higher. Does not touch `DataKey::ContractVersion`
/// itself unless it is *the* step responsible for that transition — see
/// [`migrate_legacy_to_v1`].
pub type MigrationStep = fn(&Env) -> Result<(), QuickexError>;

/// The migration step registry: the explicit, ordered step for upgrading
/// away from `from_version`. `None` means no step is registered for that
/// version, which [`run_with`] treats as `InvalidContractVersion`.
fn step_for(from_version: u32) -> Option<MigrationStep> {
    match from_version {
        storage::LEGACY_CONTRACT_VERSION => Some(migrate_legacy_to_v1),
        _ => None,
    }
}

/// Legacy (pre-versioning) → v1: stamp the schema version and mark the
/// contract initialized. Infallible today, but returns `Result` like every
/// step so a future revision of this step (or any later one) can fail
/// closed without an API change.
fn migrate_legacy_to_v1(env: &Env) -> Result<(), QuickexError> {
    storage::set_contract_version(env, 1);
    storage::set_initialized(env, true);
    Ok(())
}

/// Apply every registered step from `from_version` up to `to_version`, in
/// order, using the real production registry ([`step_for`]).
///
/// Returns the version reached, which equals `to_version` on success.
/// `from_version == to_version` is a no-op — the loop never runs a step.
pub fn run(env: &Env, from_version: u32, to_version: u32) -> Result<u32, QuickexError> {
    run_with(env, from_version, to_version, step_for)
}

/// Generic step-runner: applies `registry(v)` for every `v` in
/// `[from_version, to_version)`, one version at a time, in order.
///
/// Stops at the first step that returns `Err`, or the first version in
/// range with no registered step (`InvalidContractVersion`) — either way,
/// later steps never run. Parameterized over the registry purely so tests
/// can exercise multi-step/failure scenarios with a fake one; production
/// always calls this through [`run`].
pub fn run_with(
    env: &Env,
    from_version: u32,
    to_version: u32,
    registry: impl Fn(u32) -> Option<MigrationStep>,
) -> Result<u32, QuickexError> {
    let mut version = from_version;
    while version < to_version {
        let step = registry(version).ok_or(QuickexError::InvalidContractVersion)?;
        step(env)?;
        version += 1;
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{vec as sorobanvec, Address, Symbol, Vec};

    /// A bare env with a registered (but uninitialized) contract to host
    /// storage — `run`/`run_with` touch `env.storage()`, which requires an
    /// active contract context. `crate::QuickexContract` is registered but
    /// never `initialize`d; these tests only exercise the step-runner and
    /// the raw storage helpers a step calls, not the full contract.
    fn setup() -> (Env, Address) {
        let env = Env::default();
        let contract_id = env.register(crate::QuickexContract, ());
        (env, contract_id)
    }

    /// Records each fake step's version number, in call order, into
    /// temporary storage — a `no_std`-friendly stand-in for a `Vec` a
    /// closure would otherwise need `alloc` to capture.
    fn log(env: &Env, step: u32) {
        let key = Symbol::new(env, "mig_test_log");
        let mut v: Vec<u32> = env.storage().temporary().get(&key).unwrap_or(Vec::new(env));
        v.push_back(step);
        env.storage().temporary().set(&key, &v);
    }

    fn read_log(env: &Env) -> Vec<u32> {
        let key = Symbol::new(env, "mig_test_log");
        env.storage().temporary().get(&key).unwrap_or(Vec::new(env))
    }

    fn step_0(env: &Env) -> Result<(), QuickexError> {
        log(env, 0);
        Ok(())
    }
    fn step_1(env: &Env) -> Result<(), QuickexError> {
        log(env, 1);
        Ok(())
    }
    fn step_2_fails(env: &Env) -> Result<(), QuickexError> {
        log(env, 2);
        Err(QuickexError::InternalError)
    }
    fn step_3(env: &Env) -> Result<(), QuickexError> {
        log(env, 3);
        Ok(())
    }

    /// Fake 4-version registry (0->1->2->3->4) where the 2->3 step always
    /// fails, used only to exercise `run_with`'s control flow in isolation.
    fn fake_registry(from_version: u32) -> Option<MigrationStep> {
        match from_version {
            0 => Some(step_0),
            1 => Some(step_1),
            2 => Some(step_2_fails),
            3 => Some(step_3),
            _ => None,
        }
    }

    #[test]
    fn single_step_applies_exactly_one_version() {
        let (env, contract_id) = setup();
        env.as_contract(&contract_id, || {
            let result = run_with(&env, 0, 1, fake_registry);
            assert_eq!(result, Ok(1));
            assert_eq!(read_log(&env), sorobanvec![&env, 0]);
        });
    }

    #[test]
    fn multi_step_applies_each_intermediate_step_in_order() {
        let (env, contract_id) = setup();
        env.as_contract(&contract_id, || {
            let result = run_with(&env, 0, 2, fake_registry);
            assert_eq!(result, Ok(2));
            assert_eq!(read_log(&env), sorobanvec![&env, 0, 1]);
        });
    }

    #[test]
    fn no_op_when_already_at_the_target_version() {
        let (env, contract_id) = setup();
        env.as_contract(&contract_id, || {
            let result = run_with(&env, 1, 1, fake_registry);
            assert_eq!(result, Ok(1));
            assert_eq!(
                read_log(&env),
                Vec::new(&env),
                "no step should run when from == to"
            );
        });
    }

    #[test]
    fn mid_migration_failure_stops_before_running_later_steps() {
        let (env, contract_id) = setup();
        env.as_contract(&contract_id, || {
            let result = run_with(&env, 0, 4, fake_registry);
            assert_eq!(result, Err(QuickexError::InternalError));
            assert_eq!(
                read_log(&env),
                sorobanvec![&env, 0, 1, 2],
                "steps 0 and 1 must have run, step 2 must have run and failed, \
                 step 3 must never run"
            );
        });
    }

    #[test]
    fn missing_step_for_an_intermediate_version_fails_closed() {
        let (env, contract_id) = setup();
        env.as_contract(&contract_id, || {
            // No arm exists for version 10 in fake_registry.
            let result = run_with(&env, 10, 11, fake_registry);
            assert_eq!(result, Err(QuickexError::InvalidContractVersion));
        });
    }

    #[test]
    fn production_registry_applies_the_real_legacy_to_v1_step() {
        let (env, contract_id) = setup();
        env.as_contract(&contract_id, || {
            let result = run(&env, storage::LEGACY_CONTRACT_VERSION, 1);
            assert_eq!(result, Ok(1));
            assert_eq!(storage::get_contract_version(&env), Some(1));
            assert!(storage::is_initialized(&env));
        });
    }

    #[test]
    fn production_registry_is_a_no_op_at_the_current_version() {
        let (env, contract_id) = setup();
        env.as_contract(&contract_id, || {
            let result = run(&env, 1, 1);
            assert_eq!(result, Ok(1));
            // No step ran, so nothing was written.
            assert_eq!(storage::get_contract_version(&env), None);
        });
    }
}
