//! Canonical smoke-scenario test suite for the QuickEx contract.
//!
//! Every scenario declared in `smoke-scenarios.json` is validated twice:
//!
//! 1. **Artifact validity** — the exported JSON is structurally sound:
//!    unique `SMOKE-NNN` ids, known contract entry points, and error codes
//!    that actually exist on-chain. If the artifact drifts from the contract
//!    (e.g. a scenario references an unknown method or an error code that was
//!    renumbered), these tests fail.
//! 2. **Behavior alignment** — each scenario's declared `expected_outcome` /
//!    `expected_error` is exercised against the deployed contract so contract
//!    behavior provably matches the exported artifact.
//!
//! Consumers (backend deploy tooling, CI, contributors) can therefore trust
//! that `smoke-scenarios.json` describes exactly what the contract does.

extern crate std;

use std::{collections::HashSet, string::String, vec::Vec};

use serde::Deserialize;

use crate::{
    assert_helpers::{
        assert_escrow_pending, assert_escrow_refunded, assert_escrow_spent, assert_qx_err,
    },
    errors::QuickexError,
    events::EVENT_SCHEMA_VERSION,
    storage::CURRENT_CONTRACT_VERSION,
    test_context::TestContext,
};

/// Raw exported JSON artifact included at compile time.
const SMOKE_SCENARIOS_JSON: &str = include_str!("../smoke-scenarios.json");

// ---------------------------------------------------------------------------
// Artifact model (subset of fields the tests consume)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ScenarioError {
    name: String,
    code: u32,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Scenario {
    id: String,
    name: String,
    #[serde(default)]
    description: String,
    category: String,
    entry_point: String,
    expected_outcome: String,
    expected_error: Option<ScenarioError>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ScenariosArtifact {
    kind: String,
    version: String,
    contract: String,
    scenarios: Vec<Scenario>,
}

fn artifact() -> ScenariosArtifact {
    serde_json::from_str(SMOKE_SCENARIOS_JSON)
        .expect("smoke-scenarios.json must parse as valid JSON matching the schema")
}

fn scenario<'a>(artifact: &'a ScenariosArtifact, id: &str) -> &'a Scenario {
    artifact
        .scenarios
        .iter()
        .find(|s| s.id == id)
        .unwrap_or_else(|| panic!("smoke-scenarios.json is missing scenario {id}"))
}

/// Assert that a scenario is declared as a rejection with the given error.
fn assert_rejection(scenario: &Scenario, error_name: &str, code: u32) {
    assert_eq!(
        scenario.expected_outcome, "rejection",
        "scenario {} must be declared as a rejection",
        scenario.id
    );
    let err = scenario
        .expected_error
        .as_ref()
        .unwrap_or_else(|| panic!("scenario {} must declare expected_error", scenario.id));
    assert_eq!(
        err.name, error_name,
        "scenario {} declares wrong error name",
        scenario.id
    );
    assert_eq!(
        err.code, code,
        "scenario {} declares wrong error code",
        scenario.id
    );
}

// ---------------------------------------------------------------------------
// Artifact validity
// ---------------------------------------------------------------------------

#[test]
fn artifact_is_well_formed() {
    let artifact = artifact();
    assert_eq!(artifact.kind, "quickex-smoke-scenarios-v1");
    assert_eq!(artifact.version, "1.0.0");
    assert_eq!(artifact.contract, "quickex");
    assert!(
        !artifact.scenarios.is_empty(),
        "artifact must declare at least one scenario"
    );
}

#[test]
fn artifact_scenario_ids_are_unique_and_well_formed() {
    let artifact = artifact();
    let mut seen = HashSet::new();
    for s in &artifact.scenarios {
        assert!(
            s.id.len() == 9
                && s.id.starts_with("SMOKE-")
                && s.id[6..].chars().all(|c| c.is_ascii_digit()),
            "scenario id {} must match SMOKE-NNN",
            s.id
        );
        assert!(seen.insert(s.id.clone()), "duplicate scenario id {}", s.id);
        assert!(!s.name.is_empty(), "scenario {} missing name", s.id);
        assert!(
            !s.entry_point.is_empty(),
            "scenario {} missing entry_point",
            s.id
        );
        assert!(
            s.expected_outcome == "success" || s.expected_outcome == "rejection",
            "scenario {} has invalid expected_outcome '{}'",
            s.id,
            s.expected_outcome
        );
        if s.expected_outcome == "rejection" {
            assert!(
                s.expected_error.is_some(),
                "rejection scenario {} must declare expected_error",
                s.id
            );
        }
    }
}

#[test]
fn artifact_entry_points_are_known_contract_methods() {
    const KNOWN_ENTRY_POINTS: &[&str] = &[
        "health_check",
        "get_deployment_metadata",
        "initialize",
        "create_amount_commitment",
        "verify_amount_commitment",
        "deposit",
        "withdraw",
        "refund",
        "dispute",
        "resolve_dispute",
        "set_privacy",
        "get_privacy",
    ];
    let artifact = artifact();
    for s in &artifact.scenarios {
        assert!(
            KNOWN_ENTRY_POINTS.contains(&s.entry_point.as_str()),
            "scenario {} references unknown entry point '{}'",
            s.id,
            s.entry_point
        );
    }
}

#[test]
fn artifact_error_codes_match_contract_errors() {
    const KNOWN_ERRORS: &[(QuickexError, &str)] = &[
        (QuickexError::InvalidAmount, "InvalidAmount"),
        (QuickexError::AlreadyInitialized, "AlreadyInitialized"),
        (QuickexError::PrivacyAlreadySet, "PrivacyAlreadySet"),
        (
            QuickexError::CommitmentAlreadyExists,
            "CommitmentAlreadyExists",
        ),
        (QuickexError::AlreadySpent, "AlreadySpent"),
        (QuickexError::EscrowNotExpired, "EscrowNotExpired"),
        (QuickexError::NoArbiter, "NoArbiter"),
        (QuickexError::NotArbiter, "NotArbiter"),
    ];
    let artifact = artifact();
    for s in &artifact.scenarios {
        if let Some(err) = &s.expected_error {
            let matched = KNOWN_ERRORS
                .iter()
                .any(|(variant, name)| *name == err.name && *variant as u32 == err.code);
            assert!(
                matched,
                "scenario {} references unknown error ({}: {})",
                s.id, err.name, err.code
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Behavior alignment (SMOKE-001 .. SMOKE-016)
// ---------------------------------------------------------------------------

#[test]
fn smoke_001_health_check() {
    let artifact = artifact();
    let s = scenario(&artifact, "SMOKE-001");
    assert_eq!(s.expected_outcome, "success");
    let ctx = TestContext::new();
    assert!(
        ctx.client.health_check(),
        "SMOKE-001: health_check must return true"
    );
}

#[test]
fn smoke_002_get_deployment_metadata() {
    let artifact = artifact();
    let s = scenario(&artifact, "SMOKE-002");
    assert_eq!(s.expected_outcome, "success");
    let ctx = TestContext::with_admin();
    let meta = ctx.client.get_deployment_metadata();
    assert_eq!(meta.contract_version, CURRENT_CONTRACT_VERSION);
    assert_eq!(meta.event_schema_version, EVENT_SCHEMA_VERSION);
}

#[test]
fn smoke_003_initialize_already_initialized() {
    let artifact = artifact();
    let s = scenario(&artifact, "SMOKE-003");
    assert_rejection(s, "AlreadyInitialized", 201);
    let ctx = TestContext::with_admin();
    assert_qx_err(
        ctx.client.try_initialize(&ctx.admin),
        QuickexError::AlreadyInitialized,
    );
}

#[test]
fn smoke_004_create_amount_commitment_success() {
    let artifact = artifact();
    let s = scenario(&artifact, "SMOKE-004");
    assert_eq!(s.expected_outcome, "success");
    let ctx = TestContext::new();
    let salt = ctx.salt(b"smoke_salt_001");
    let commitment = ctx
        .client
        .create_amount_commitment(&ctx.alice, &1000, &salt);
    assert!(
        ctx.client
            .verify_amount_commitment(&commitment, &ctx.alice, &1000, &salt),
        "SMOKE-004: created commitment must verify"
    );
}

#[test]
fn smoke_005_create_amount_commitment_negative_amount() {
    let artifact = artifact();
    let s = scenario(&artifact, "SMOKE-005");
    assert_rejection(s, "InvalidAmount", 100);
    let ctx = TestContext::new();
    let salt = ctx.salt(b"smoke_salt_001");
    assert_qx_err(
        ctx.client
            .try_create_amount_commitment(&ctx.alice, &-500, &salt),
        QuickexError::InvalidAmount,
    );
}

#[test]
fn smoke_006_008_deposit_lifecycle() {
    let artifact = artifact();
    let s006 = scenario(&artifact, "SMOKE-006");
    let s007 = scenario(&artifact, "SMOKE-007");
    let s008 = scenario(&artifact, "SMOKE-008");
    assert_eq!(s006.expected_outcome, "success");
    assert_rejection(s007, "InvalidAmount", 100);
    assert_rejection(s008, "CommitmentAlreadyExists", 303);

    let ctx = TestContext::with_fees(0);

    // SMOKE-007: a zero-amount deposit must be rejected.
    assert_qx_err(
        ctx.client.try_deposit(
            &ctx.token,
            &0,
            &ctx.alice,
            &ctx.salt(b"smoke_salt_deposit_zero"),
            &0,
            &None,
            &TestContext::TEST_DEPOSIT_NONCE,
            &TestContext::TEST_DEPOSIT_VALID_UNTIL,
        ),
        QuickexError::InvalidAmount,
    );

    // SMOKE-006: a valid deposit creates a pending escrow.
    let commitment = ctx.simple_deposit(&ctx.alice, 1000, b"smoke_salt_deposit_1");
    assert_escrow_pending(&ctx.client, &commitment);

    // SMOKE-008: re-depositing the same commitment (different escrow id and
    // nonce so the replay-protection registry is bypassed) is rejected.
    assert_qx_err(
        ctx.client.try_deposit(
            &ctx.token,
            &1000,
            &ctx.alice,
            &ctx.salt(b"smoke_salt_deposit_1"),
            &3600,
            &None,
            &1u64,
            &TestContext::TEST_DEPOSIT_VALID_UNTIL,
        ),
        QuickexError::CommitmentAlreadyExists,
    );
}

#[test]
fn smoke_009_010_withdraw_lifecycle() {
    let artifact = artifact();
    let s009 = scenario(&artifact, "SMOKE-009");
    let s010 = scenario(&artifact, "SMOKE-010");
    assert_eq!(s009.expected_outcome, "success");
    assert_rejection(s010, "AlreadySpent", 304);

    let ctx = TestContext::with_fees(0);
    let salt = b"smoke_salt_deposit_1";
    let commitment = ctx.simple_deposit(&ctx.alice, 1000, salt);

    // SMOKE-009: the depositor withdraws the escrow successfully.
    let ok = ctx.client.withdraw(
        &ctx.token,
        &1000,
        &commitment,
        &ctx.alice,
        &ctx.salt(salt),
        &TestContext::TEST_DEPOSIT_NONCE,
        &TestContext::TEST_DEPOSIT_VALID_UNTIL,
    );
    assert!(ok, "SMOKE-009: withdraw must return true");
    assert_escrow_spent(&ctx.client, &commitment);

    // SMOKE-010: withdrawing a spent escrow is rejected (with a fresh nonce
    // so the replay-protection registry is bypassed).
    assert_qx_err(
        ctx.client.try_withdraw(
            &ctx.token,
            &1000,
            &commitment,
            &ctx.alice,
            &ctx.salt(salt),
            &1u64,
            &TestContext::TEST_DEPOSIT_VALID_UNTIL,
        ),
        QuickexError::AlreadySpent,
    );
}

#[test]
fn smoke_011_012_refund_lifecycle() {
    let artifact = artifact();
    let s011 = scenario(&artifact, "SMOKE-011");
    let s012 = scenario(&artifact, "SMOKE-012");
    assert_rejection(s011, "EscrowNotExpired", 308);
    assert_eq!(s012.expected_outcome, "success");

    let ctx = TestContext::with_fees(0);
    let commitment = ctx.deposit_with_arbiter(&ctx.alice, 1000, b"smoke_salt_refund_1", 3600);

    // SMOKE-011: refund before the timeout elapses is rejected.
    assert_qx_err(
        ctx.client.try_refund(
            &commitment,
            &ctx.alice,
            &TestContext::TEST_DEPOSIT_NONCE,
            &TestContext::TEST_DEPOSIT_VALID_UNTIL,
        ),
        QuickexError::EscrowNotExpired,
    );

    // SMOKE-012: after the timeout the owner can refund.
    ctx.advance_time(3601);
    ctx.client.refund(
        &commitment,
        &ctx.alice,
        &TestContext::TEST_DEPOSIT_NONCE,
        &TestContext::TEST_DEPOSIT_VALID_UNTIL,
    );
    assert_escrow_refunded(&ctx.client, &commitment);
}

#[test]
fn smoke_013_014_dispute_lifecycle() {
    let artifact = artifact();
    let s013 = scenario(&artifact, "SMOKE-013");
    let s014 = scenario(&artifact, "SMOKE-014");
    assert_rejection(s013, "NoArbiter", 310);
    assert_rejection(s014, "NotArbiter", 312);

    let ctx = TestContext::with_fees(0);

    // SMOKE-013: an escrow without an arbiter cannot be disputed.
    let no_arbiter = ctx.simple_deposit(&ctx.alice, 1000, b"smoke_salt_no_arbiter");
    assert_qx_err(ctx.client.try_dispute(&no_arbiter), QuickexError::NoArbiter);

    // SMOKE-014: a non-arbiter cannot resolve a disputed escrow. Mint and
    // deposit manually with a fresh nonce (nonce 0 was consumed above).
    ctx.mint(&ctx.alice, 1000);
    let disputed = ctx.client.deposit(
        &ctx.token,
        &1000,
        &ctx.alice,
        &ctx.salt(b"smoke_salt_with_arbiter"),
        &3600,
        &Some(ctx.arbiter.clone()),
        &1u64,
        &TestContext::TEST_DEPOSIT_VALID_UNTIL,
    );
    ctx.client.dispute(&disputed);
    assert_qx_err(
        ctx.client.try_resolve_dispute(
            &ctx.alice,
            &disputed,
            &true,
            &ctx.bob,
            &TestContext::TEST_DEPOSIT_NONCE,
            &TestContext::TEST_DEPOSIT_VALID_UNTIL,
        ),
        QuickexError::NotArbiter,
    );
}

#[test]
fn smoke_015_016_privacy_lifecycle() {
    let artifact = artifact();
    let s015 = scenario(&artifact, "SMOKE-015");
    let s016 = scenario(&artifact, "SMOKE-016");
    assert_eq!(s015.expected_outcome, "success");
    assert_rejection(s016, "PrivacyAlreadySet", 301);

    let ctx = TestContext::with_admin();

    // SMOKE-015: enabling privacy succeeds and is observable.
    ctx.client.set_privacy(&ctx.alice, &true);
    assert!(
        ctx.client.get_privacy(&ctx.alice),
        "SMOKE-015: privacy must be enabled"
    );

    // SMOKE-016: setting privacy to the same value is rejected.
    assert_qx_err(
        ctx.client.try_set_privacy(&ctx.alice, &true),
        QuickexError::PrivacyAlreadySet,
    );
}
