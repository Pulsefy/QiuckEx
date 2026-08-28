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
    ctx.client.set_paused(&operator, &true, &1u32);
    assert!(ctx.client.is_paused());

    // Alice unpauses
    ctx.client.set_paused(&operator, &false, &0u32);
    assert!(!ctx.client.is_paused());
}

#[test]
fn test_admin_inherits_operator_permissions() {
    let ctx = TestContext::with_admin();

    ctx.client.set_paused(&ctx.admin, &true, &1u32);
    assert!(ctx.client.is_paused());

    ctx.client.set_paused(&ctx.admin, &false, &0u32);
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
        &0u64,
        &u64::MAX,
    );

    // Dispute it
    ctx.client.dispute(&commitment);

    // Global arbiter (Bob) resolves it
    ctx.client.resolve_dispute(
        &global_arbiter,
        &commitment,
        &true,
        &ctx.alice,
        &0u64,
        &u64::MAX,
    );

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

#[test]
fn test_multisig_requires_quorum_for_admin_action() {
    let env = soroban_sdk::Env::default();
    env.mock_all_auths();
    let contract_id = env.register(crate::QuickexContract, ());
    let client = crate::QuickexContractClient::new(&env, &contract_id);
    let first = Address::generate(&env);
    let second = Address::generate(&env);
    let signers = soroban_sdk::vec![&env, first.clone(), second.clone()];

    client.initialize_multisig(&signers, &2);
    assert_eq!(client.get_admin_signers(), signers);
    assert_eq!(client.get_admin_threshold(), 2);

    client.approve_admin_action(&first);
    let result = client.try_set_platform_wallet(&first, &Address::generate(&env));
    assert!(matches!(result, Err(Ok(QuickexError::InsufficientVotes))));

    client.approve_admin_action(&second);
    client.set_platform_wallet(&first, &Address::generate(&env));
    assert_eq!(client.get_admin_threshold(), 2);
}

#[test]
fn test_multisig_rejects_duplicate_approval() {
    let env = soroban_sdk::Env::default();
    env.mock_all_auths();
    let contract_id = env.register(crate::QuickexContract, ());
    let client = crate::QuickexContractClient::new(&env, &contract_id);
    let first = Address::generate(&env);
    let second = Address::generate(&env);
    let signers = soroban_sdk::vec![&env, first.clone(), second];

    client.initialize_multisig(&signers, &2);
    client.approve_admin_action(&first);
    let result = client.try_approve_admin_action(&first);
    assert!(matches!(
        result,
        Err(Ok(QuickexError::AdminActionAlreadyApproved))
    ));
}
