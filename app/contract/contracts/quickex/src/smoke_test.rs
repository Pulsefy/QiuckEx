//! Smoke test suite for post-deploy scenario verification.
//!
//! Validates that contract execution matches the canonical smoke scenario spec
//! exported in `smoke-scenarios.json`.

use crate::{errors::QuickexError, test_context::TestContext, EscrowStatus};

/// Raw exported JSON artifact included at compile time.
const SMOKE_SCENARIOS_JSON: &str = include_str!("../smoke-scenarios.json");

#[test]
fn test_smoke_artifact_manifest_validity() {
    assert!(
        SMOKE_SCENARIOS_JSON.contains("\"version\": \"1.0.0\""),
        "Manifest must specify valid schema version 1.0.0"
    );
    assert!(
        SMOKE_SCENARIOS_JSON.contains("\"contract\": \"quickex\""),
        "Manifest must target quickex contract"
    );

    let scenario_ids = [
        "SMOKE-001",
        "SMOKE-002",
        "SMOKE-003",
        "SMOKE-004",
        "SMOKE-005",
        "SMOKE-006",
        "SMOKE-007",
        "SMOKE-008",
        "SMOKE-009",
        "SMOKE-010",
        "SMOKE-011",
        "SMOKE-012",
        "SMOKE-013",
        "SMOKE-014",
        "SMOKE-015",
        "SMOKE-016",
    ];

    for id in scenario_ids {
        assert!(
            SMOKE_SCENARIOS_JSON.contains(id),
            "Manifest missing scenario ID {}",
            id
        );
    }
}

#[test]
fn test_smoke_scenario_001_health_check() {
    let ctx = TestContext::new();
    let is_healthy = ctx.client.health_check();
    assert!(is_healthy, "health_check scenario SMOKE-001 must return true");
}

#[test]
fn test_smoke_scenario_002_get_deployment_metadata() {
    let ctx = TestContext::with_admin();
    let meta = ctx.client.get_deployment_metadata();
    assert_eq!(
        meta.contract_version, 1,
        "SMOKE-002: metadata contract version mismatch"
    );
    assert_eq!(
        meta.event_schema_version, 1,
        "SMOKE-002: metadata event schema version mismatch"
    );
}

#[test]
fn test_smoke_scenario_003_initialize_already_initialized() {
    let ctx = TestContext::with_admin();
    let res = ctx.client.try_initialize(&ctx.admin);
    assert_eq!(
        res,
        Err(Ok(QuickexError::AlreadyInitialized)),
        "SMOKE-003: expected AlreadyInitialized (code 201)"
    );
}

#[test]
fn test_smoke_scenario_004_create_amount_commitment_success() {
    let ctx = TestContext::new();
    let salt = ctx.salt(b"smoke_salt_001");
    let commitment = ctx
        .client
        .create_amount_commitment(&ctx.alice, &1000, &salt);
    let is_valid =
        ctx.client
            .verify_amount_commitment(&commitment, &ctx.alice, &1000, &salt);
    assert!(
        is_valid,
        "SMOKE-004: created commitment failed verification"
    );
}

#[test]
fn test_smoke_scenario_005_create_amount_commitment_invalid_amount() {
    let ctx = TestContext::new();
    let salt = ctx.salt(b"smoke_salt_001");
    let res = ctx
        .client
        .try_create_amount_commitment(&ctx.alice, &-500, &salt);
    assert_eq!(
        res,
        Err(Ok(QuickexError::InvalidAmount)),
        "SMOKE-005: expected InvalidAmount (code 100)"
    );
}

#[test]
fn test_smoke_scenario_006_to_010_escrow_deposit_withdraw_lifecycle() {
    let ctx = TestContext::with_fees(0);
    let salt = b"smoke_salt_deposit_1";

    // SMOKE-007: Deposit zero amount -> InvalidAmount (100)
    let res_zero = ctx.client.try_deposit(
        &ctx.token,
        &0,
        &ctx.alice,
        &ctx.salt(b"smoke_salt_deposit_zero"),
        &3600,
        &None,
        &TestContext::TEST_DEPOSIT_NONCE,
        &TestContext::TEST_DEPOSIT_VALID_UNTIL,
    );
    assert_eq!(
        res_zero,
        Err(Ok(QuickexError::InvalidAmount)),
        "SMOKE-007: expected InvalidAmount (code 100)"
    );

    // SMOKE-006: Deposit success
    let commitment = ctx.simple_deposit(&ctx.alice, 1000, salt);
    assert_eq!(
        ctx.client.get_commitment_state(&commitment),
        Some(EscrowStatus::Pending),
        "SMOKE-006: escrow status should be Pending"
    );

    // SMOKE-008: Deposit duplicate commitment -> CommitmentAlreadyExists (303)
    let res_dup = ctx.client.try_deposit(
        &ctx.token,
        &1000,
        &ctx.alice,
        &ctx.salt(salt),
        &0,
        &None,
        &TestContext::TEST_DEPOSIT_NONCE,
        &TestContext::TEST_DEPOSIT_VALID_UNTIL,
    );
    assert_eq!(
        res_dup,
        Err(Ok(QuickexError::CommitmentAlreadyExists)),
        "SMOKE-008: expected CommitmentAlreadyExists (code 303)"
    );

    // SMOKE-009: Withdraw success
    let res_withdraw = ctx.client.withdraw(
        &ctx.token,
        &1000,
        &commitment,
        &ctx.bob,
        &ctx.salt(salt),
        &TestContext::TEST_DEPOSIT_NONCE,
        &TestContext::TEST_DEPOSIT_VALID_UNTIL,
    );
    assert!(res_withdraw, "SMOKE-009: withdraw should return true");
    assert_eq!(
        ctx.client.get_commitment_state(&commitment),
        Some(EscrowStatus::Spent),
        "SMOKE-009: escrow status should be Spent"
    );

    // SMOKE-010: Withdraw already spent -> AlreadySpent (304)
    let res_spent = ctx.client.try_withdraw(
        &ctx.token,
        &1000,
        &commitment,
        &ctx.bob,
        &ctx.salt(salt),
        &TestContext::TEST_DEPOSIT_NONCE,
        &TestContext::TEST_DEPOSIT_VALID_UNTIL,
    );
    assert_eq!(
        res_spent,
        Err(Ok(QuickexError::AlreadySpent)),
        "SMOKE-010: expected AlreadySpent (code 304)"
    );
}

#[test]
fn test_smoke_scenario_011_and_012_refund_lifecycle() {
    let ctx = TestContext::with_fees(0);
    let salt = b"smoke_salt_refund_1";

    // Create escrow with 3600 sec timeout
    let commitment = ctx.deposit_with_arbiter(&ctx.alice, 1000, salt, 3600);

    // SMOKE-011: Refund before timeout -> EscrowNotExpired (308)
    let res_not_expired = ctx.client.try_refund(
        &commitment,
        &ctx.alice,
        &TestContext::TEST_DEPOSIT_NONCE,
        &TestContext::TEST_DEPOSIT_VALID_UNTIL,
    );
    assert_eq!(
        res_not_expired,
        Err(Ok(QuickexError::EscrowNotExpired)),
        "SMOKE-011: expected EscrowNotExpired (code 308)"
    );

    // SMOKE-012: Refund after timeout expiry -> Success
    ctx.advance_time(3601);
    let res_refund = ctx.client.refund(
        &commitment,
        &ctx.alice,
        &TestContext::TEST_DEPOSIT_NONCE,
        &TestContext::TEST_DEPOSIT_VALID_UNTIL,
    );
    assert_eq!(res_refund, (), "SMOKE-012: refund should succeed");
    assert_eq!(
        ctx.client.get_commitment_state(&commitment),
        Some(EscrowStatus::Refunded),
        "SMOKE-012: escrow status should be Refunded"
    );
}

#[test]
fn test_smoke_scenario_013_and_014_dispute_lifecycle() {
    let ctx = TestContext::with_fees(0);
    let salt_no_arbiter = b"smoke_salt_no_arbiter";
    let salt_with_arbiter = b"smoke_salt_with_arbiter";

    // Escrow without arbiter
    let commitment_no_arbiter = ctx.simple_deposit(&ctx.alice, 1000, salt_no_arbiter);

    // SMOKE-013: Dispute escrow without arbiter -> NoArbiter (310)
    let res_no_arbiter = ctx.client.try_dispute(&commitment_no_arbiter);
    assert_eq!(
        res_no_arbiter,
        Err(Ok(QuickexError::NoArbiter)),
        "SMOKE-013: expected NoArbiter (code 310)"
    );

    // Escrow with arbiter
    let commitment_with_arbiter = ctx.deposit_with_arbiter(&ctx.alice, 1000, salt_with_arbiter, 3600);
    ctx.client.dispute(&commitment_with_arbiter);

    // SMOKE-014: Non-arbiter resolving dispute -> NotArbiter (312)
    let res_not_arbiter = ctx.client.try_resolve_dispute(
        &ctx.alice,
        &commitment_with_arbiter,
        &true,
        &ctx.bob,
        &TestContext::TEST_DEPOSIT_NONCE,
        &TestContext::TEST_DEPOSIT_VALID_UNTIL,
    );
    assert_eq!(
        res_not_arbiter,
        Err(Ok(QuickexError::NotArbiter)),
        "SMOKE-014: expected NotArbiter (code 312)"
    );
}

#[test]
fn test_smoke_scenario_015_and_016_privacy_lifecycle() {
    let ctx = TestContext::with_admin();

    // SMOKE-015: Set privacy success
    let res_set = ctx.client.set_privacy(&ctx.alice, &true);
    assert_eq!(res_set, (), "SMOKE-015: set_privacy should succeed");
    assert!(
        ctx.client.get_privacy(&ctx.alice),
        "SMOKE-015: get_privacy should return true"
    );

    // SMOKE-016: Set privacy when already enabled -> PrivacyAlreadySet (301)
    let res_already_set = ctx.client.try_set_privacy(&ctx.alice, &true);
    assert_eq!(
        res_already_set,
        Err(Ok(QuickexError::PrivacyAlreadySet)),
        "SMOKE-016: expected PrivacyAlreadySet (code 301)"
    );
}
