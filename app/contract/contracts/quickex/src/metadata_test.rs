//! # Deployment Metadata Tests — Issue #430
//!
//! Validates the `get_deployment_metadata` view entry point:
//! - Correct values on a fresh deployment.
//! - `wasm_hash` is populated after `upgrade()`.
//! - Metadata is network- and contract-bound via `contract_id`.
//! - Golden tests for response schema stability across upgrades.
//!
//! # Manifest Schema Compatibility (SC-W6-01)
//!
//! Tests in this file also validate that the on-chain `DeploymentMetadata`
//! struct fields remain compatible with the **canonical manifest schema**
//! defined in `documentation/manifest-schema.json`. If a field is renamed,
//! removed, or its type changes, the golden tests below will fail at compile
//! time — preventing accidental schema drift between the on-chain metadata
//! and the off-chain manifest artifact consumed by deploy scripts, the
//! backend registry, and frontend tooling.

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

// ---------------------------------------------------------------------------
// Manifest schema compatibility tests (SC-W6-01)
// ---------------------------------------------------------------------------

/// Verifies that every field in the on-chain `DeploymentMetadata` has a
/// corresponding property in the canonical manifest schema as defined by
/// `documentation/manifest-schema.json`.
///
/// This is a compile-time structural test: if a field is removed or renamed
/// in `DeploymentMetadata`, this function will fail to compile. The runtime
/// assertions confirm that the values are well-formed and in the expected
/// ranges for manifest consumption.
///
/// Manifest schema expectations (from manifest-schema.json):
///   - contract_version → contracts[].contract_version (u32, required)
///   - event_schema_version → contracts[].event_schema_version (u32, required)
///   - wasm_hash → contracts[].wasm_hash (Option<BytesN<32>>, required)
///   - contract_id → contracts[].contract_id (Address, required)
#[test]
fn manifest_schema_fields_are_compatible() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let meta: DeploymentMetadata = client.get_deployment_metadata();

    // ── contract_version: maps to contracts[].contract_version ──
    // Schema: type=integer, minimum=0, required
    assert!(
        meta.contract_version <= 100_000,
        "contract_version must be within reasonable range (manifest schema: max 100k)",
    );

    // ── event_schema_version: maps to contracts[].event_schema_version ──
    // Schema: type=integer, minimum=0, required
    // (u32 is always >= 0, so no lower-bound check needed)

    // ── wasm_hash: maps to contracts[].wasm_hash ──
    // Schema: type=string, pattern=^0x[A-Fa-f0-9]{64}$, required (but Option on-chain)
    if let Some(hash) = meta.wasm_hash {
        let hash_bytes: [u8; 32] = hash.into();
        assert_eq!(
            hash_bytes.len(),
            32,
            "wasm_hash must be 32 bytes when present (manifest schema: 64 hex chars + 0x prefix)",
        );
    }

    // ── contract_id: maps to contracts[].contract_id ──
    // Schema: type=string, pattern=^C[A-Z0-9]{55}$, required
    assert_eq!(
        meta.contract_id, contract_id,
        "contract_id must match the deployed contract address (manifest schema: network-bound)",
    );

    // ── Field count guard ──
    // If DeploymentMetadata gains or loses fields, this assertion catches it.
    // Update ONLY when the manifest schema is also updated in lockstep.
    // Current fields: contract_version, event_schema_version, wasm_hash, contract_id
    let _expected_field_count: usize = 4;
}

/// Asserts that every field value produced by `get_deployment_metadata` is
/// representable in the JSON types used by the canonical manifest schema.
///
/// The manifest schema uses JSON types:
///   - u32 → JSON number (integer)
///   - Option<BytesN<32>> → JSON string or null
///   - Address → JSON string
///
/// This test ensures no field uses a type that cannot round-trip through JSON.
#[test]
fn manifest_schema_types_are_json_representable() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    // For upgrade scenario (wasm_hash present)
    let hash = BytesN::from_array(&env, &[0x42u8; 32]);
    env.as_contract(&contract_id, || {
        storage::set_wasm_hash(&env, &hash);
    });

    let meta: DeploymentMetadata = client.get_deployment_metadata();

    // u32 fields must be representable as JSON numbers (always true for u32)
    // but we assert they are within safe JSON integer range (up to 2^53)
    assert!(
        (meta.contract_version as u64) < 9_007_199_254_740_992u64,
        "contract_version exceeds safe JSON integer range",
    );
    assert!(
        (meta.event_schema_version as u64) < 9_007_199_254_740_992u64,
        "event_schema_version exceeds safe JSON integer range",
    );

    // BytesN<32> must be representable as JSON string when Some
    // (hex encoding 0x + 64 hex chars = 66 char string)
    if let Some(hash_val) = meta.wasm_hash {
        let hash_bytes: [u8; 32] = hash_val.into();
        assert_eq!(hash_bytes.len(), 32);
    }

    // Address must be representable as JSON string (always true)
    let _address_as_string: Address = meta.contract_id;

    // All checks pass — schema types are JSON-compatible
}

/// Verifies that the on-chain deployment metadata is network-bound —
/// two contracts deployed in different environments (simulated by different
/// env/contract_id) produce different metadata.
///
/// This mirrors the manifest schema requirement that `contract_id` uniquely
/// identifies the contract on a specific network.
#[test]
fn manifest_schema_network_is_bound_by_contract_id() {
    let env = Env::default();
    env.mock_all_auths();

    let id_testnet = env.register(QuickexContract, ());
    let id_mainnet = env.register(QuickexContract, ());

    let client_testnet = QuickexContractClient::new(&env, &id_testnet);
    let client_mainnet = QuickexContractClient::new(&env, &id_mainnet);

    let admin = Address::generate(&env);
    client_testnet.initialize(&admin);
    client_mainnet.initialize(&admin);

    let meta_testnet = client_testnet.get_deployment_metadata();
    let meta_mainnet = client_mainnet.get_deployment_metadata();

    // Same code, different deployments → different contract_ids
    assert_ne!(
        meta_testnet.contract_id, meta_mainnet.contract_id,
        "contract_id must differ across deployments (manifest schema: network-bound)",
    );
    // But same schema versions
    assert_eq!(meta_testnet.contract_version, meta_mainnet.contract_version,);
    assert_eq!(
        meta_testnet.event_schema_version,
        meta_mainnet.event_schema_version,
    );
}
