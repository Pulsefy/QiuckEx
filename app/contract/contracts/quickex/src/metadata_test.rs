//! # Deployment Metadata Tests — Issue #430
//!
//! Validates the `get_deployment_metadata` view entry point:
//! - Correct values on a fresh deployment.
//! - `wasm_hash` is populated after `upgrade()`.
//! - Metadata is network- and contract-bound via `contract_id`.
//! - Golden tests for response schema stability across upgrades.

use crate::{
    events::EVENT_SCHEMA_VERSION,
    storage::{self, CURRENT_CONTRACT_VERSION},
    types::DeploymentMetadata,
    QuickexContract, QuickexContractClient,
};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup() -> (Env, QuickexContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    (env, client)
}

// ---------------------------------------------------------------------------
// Basic correctness
// ---------------------------------------------------------------------------

#[test]
fn metadata_fresh_deployment_has_correct_versions() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let meta = client.get_deployment_metadata();

    assert_eq!(meta.contract_version, CURRENT_CONTRACT_VERSION);
    assert_eq!(meta.event_schema_version, EVENT_SCHEMA_VERSION);
    assert!(meta.wasm_hash.is_none());
}

#[test]
fn metadata_contract_id_matches_invoked_address() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let meta = client.get_deployment_metadata();

    assert_eq!(meta.contract_id, client.address);
}

/// Verify wasm_hash is stored by directly writing via storage (bypasses
/// `update_current_contract_wasm` which requires a real uploaded WASM in tests).
#[test]
fn metadata_wasm_hash_populated_after_upgrade() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let new_hash = BytesN::from_array(&env, &[0xabu8; 32]);
    env.as_contract(&client.address, || {
        storage::set_wasm_hash(&env, &new_hash);
    });

    let meta = client.get_deployment_metadata();
    assert_eq!(meta.wasm_hash, Some(new_hash));
}

#[test]
fn metadata_wasm_hash_updated_on_second_upgrade() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let hash_v1 = BytesN::from_array(&env, &[0x01u8; 32]);
    let hash_v2 = BytesN::from_array(&env, &[0x02u8; 32]);

    env.as_contract(&client.address, || {
        storage::set_wasm_hash(&env, &hash_v1);
        storage::set_wasm_hash(&env, &hash_v2);
    });

    let meta = client.get_deployment_metadata();
    assert_eq!(meta.wasm_hash, Some(hash_v2));
}

// ---------------------------------------------------------------------------
// Network / domain binding
// ---------------------------------------------------------------------------

#[test]
fn metadata_contract_id_differs_across_deployments() {
    // Two independent deployments must report different contract_ids,
    // ensuring metadata is bound to a specific deployment and network slot.
    let env = Env::default();
    env.mock_all_auths();

    let id_a = env.register(QuickexContract, ());
    let id_b = env.register(QuickexContract, ());

    let client_a = QuickexContractClient::new(&env, &id_a);
    let client_b = QuickexContractClient::new(&env, &id_b);

    let admin = Address::generate(&env);
    client_a.initialize(&admin);
    client_b.initialize(&admin);

    let meta_a = client_a.get_deployment_metadata();
    let meta_b = client_b.get_deployment_metadata();

    assert_ne!(meta_a.contract_id, meta_b.contract_id);
}

// ---------------------------------------------------------------------------
// Upgrade migration — versions remain correct after migrate()
// ---------------------------------------------------------------------------

#[test]
fn metadata_versions_stable_after_migrate() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    client.initialize(&admin);

    // Simulate a stored wasm_hash (as upgrade() would set) then run migration.
    let new_hash = BytesN::from_array(&env, &[0xffu8; 32]);
    env.as_contract(&client.address, || {
        storage::set_wasm_hash(&env, &new_hash);
    });
    client.migrate(&admin);

    let meta = client.get_deployment_metadata();
    assert_eq!(meta.contract_version, CURRENT_CONTRACT_VERSION);
    assert_eq!(meta.event_schema_version, EVENT_SCHEMA_VERSION);
    assert_eq!(meta.wasm_hash, Some(new_hash));
}

// ---------------------------------------------------------------------------
// Golden tests — response schema stability
// ---------------------------------------------------------------------------

/// Golden test: field names and types of DeploymentMetadata must not change.
///
/// If a field is renamed, removed, or its type changes, this test will fail
/// to compile, catching accidental breaking changes before they reach production.
#[test]
fn golden_deployment_metadata_schema_is_stable() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let hash = BytesN::from_array(&env, &[0x42u8; 32]);
    env.as_contract(&contract_id, || {
        storage::set_wasm_hash(&env, &hash);
    });

    let meta: DeploymentMetadata = client.get_deployment_metadata();

    // Assert field presence and types (compile-time + runtime).
    let _cv: u32 = meta.contract_version;
    let _esv: u32 = meta.event_schema_version;
    let _wh: Option<BytesN<32>> = meta.wasm_hash;
    let _cid: Address = meta.contract_id;

    assert_eq!(_cv, CURRENT_CONTRACT_VERSION);
    assert_eq!(_esv, EVENT_SCHEMA_VERSION);
    assert_eq!(_wh, Some(hash));
    assert_eq!(_cid, contract_id);
}

/// Golden test: metadata returned without an upgrade must have a stable shape.
#[test]
fn golden_deployment_metadata_no_upgrade_schema_is_stable() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let meta: DeploymentMetadata = client.get_deployment_metadata();

    assert_eq!(meta.contract_version, CURRENT_CONTRACT_VERSION);
    assert_eq!(meta.event_schema_version, EVENT_SCHEMA_VERSION);
    assert_eq!(meta.wasm_hash, None);
    assert_eq!(meta.contract_id, contract_id);
}
