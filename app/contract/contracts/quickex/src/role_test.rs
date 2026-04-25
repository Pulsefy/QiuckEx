use crate::{errors::QuickexError, test_context::TestContext, types::Role};
use soroban_sdk::{testutils::Address as _, Address};

#[test]
fn test_initial_admin_has_role() {
    let ctx = TestContext::with_admin();
    let roles = ctx.client.get_roles(&ctx.admin);
    assert!(roles.contains(Role::Admin));
}

#[test]
fn test_grant_and_revoke_role() {
    let ctx = TestContext::with_admin();
    let user = Address::generate(&ctx.env);

    // Grant Operator role
    ctx.client.grant_role(&ctx.admin, &user, &Role::Operator);
    let roles = ctx.client.get_roles(&user);
    assert!(roles.contains(Role::Operator));

    // Revoke Operator role
    ctx.client.revoke_role(&ctx.admin, &user, &Role::Operator);
    let roles = ctx.client.get_roles(&user);
    assert!(!roles.contains(Role::Operator));
}

#[test]
fn test_unauthorized_grant_fails() {
    let ctx = TestContext::with_admin();

    // Alice tries to grant a role to Bob
    let res = ctx
        .client
        .try_grant_role(&ctx.alice, &ctx.bob, &Role::Operator);
    assert!(res.is_err());
}

#[test]
fn test_operator_can_pause() {
    let ctx = TestContext::with_admin();
    let operator = ctx.alice.clone();

    // Grant Operator role to Alice
    ctx.client
        .grant_role(&ctx.admin, &operator, &Role::Operator);

    // Alice (Operator) pauses the contract
    ctx.client.set_paused(&operator, &true);
    assert!(ctx.client.is_paused());

    // Alice unpauses
    ctx.client.set_paused(&operator, &false);
    assert!(!ctx.client.is_paused());
}

#[test]
fn test_arbiter_role_resolution() {
    let ctx = TestContext::with_admin();
    let global_arbiter = ctx.bob.clone();

    // Grant Arbiter role to Bob
    ctx.client
        .grant_role(&ctx.admin, &global_arbiter, &Role::Arbiter);

    // Create a dispute WITHOUT a per-escrow arbiter (wait, deposit requires Option<Address>)
    // Actually, let's create it WITH a different arbiter but let the global one resolve it.
    let per_escrow_arbiter = Address::generate(&ctx.env);
    ctx.mint(&ctx.alice, 1000);
    let commitment = ctx.client.deposit(
        &ctx.token,
        &1000,
        &ctx.alice,
        &ctx.salt(b"salt"),
        &3600,
        &Some(per_escrow_arbiter.clone()),
    );

    // Dispute it
    ctx.client.dispute(&commitment);

    // Global arbiter (Bob) resolves it
    ctx.client
        .resolve_dispute(&global_arbiter, &commitment, &true, &ctx.alice);

    // Verify resolution
    let status = ctx.client.get_commitment_state(&commitment).unwrap();
    assert_eq!(status, crate::types::EscrowStatus::Refunded);
}

#[test]
fn test_insufficient_role_error() {
    let ctx = TestContext::with_admin();

    // Alice (no roles) tries to set fee config
    let res = ctx
        .client
        .try_set_fee_config(&ctx.alice, &crate::types::FeeConfig { fee_bps: 100 });

    match res {
        Err(Ok(QuickexError::InsufficientRole)) => (),
        _ => panic!("Expected InsufficientRole error"),
    }
}
