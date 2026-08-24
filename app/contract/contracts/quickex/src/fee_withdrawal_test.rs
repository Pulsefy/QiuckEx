//! Fee withdrawal entrypoint tests.
//!
//! Covers the admin-authorized `withdraw_fees` entry point:
//! - full withdrawal, partial withdrawal, over-withdrawal rejection
//! - unauthorized caller rejection (non-admin and operator)
//! - accounting invariant: withdrawals can never touch escrowed principal
//! - accrued fee balance is queryable per asset
//! - `FeesWithdrawn` event carries asset, amount, recipient, and actor
//! - pause and emergency-mode policy enforcement
//!
//! Fees accrue in the contract when a routed fee cannot be paid out (no
//! collector and/or no arbiter configured at settlement time). See
//! [`crate::fee_router`].

use crate::{
    errors::QuickexError,
    events::EVENT_SCHEMA_VERSION,
    pause_policy::EntryPoint,
    types::{FeeConfig, PerAssetFeeConfig, Role},
    EscrowStatus, QuickexContract, QuickexContractClient,
};
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger},
    token, Address, Bytes, Env, InvokeError, Map, Symbol, TryIntoVal, Val,
};

fn setup<'a>() -> (Env, QuickexContractClient<'a>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|li| li.timestamp = 1_000);

    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let token = create_token(&env);

    (env, client, admin, token)
}

fn create_token(env: &Env) -> Address {
    env.register_stellar_asset_contract_v2(Address::generate(env))
        .address()
}

/// Mint `amount` to `owner`, then deposit and withdraw with `fee_bps`
/// configured and **no collector set**, so the fee stays in the contract and
/// is credited to the accrued-fee ledger. Returns the accrued fee.
fn accrue_fee(
    env: &Env,
    client: &QuickexContractClient,
    admin: &Address,
    token: &Address,
    owner: &Address,
    fee_bps: u32,
    amount: i128,
    nonce: u64,
) -> i128 {
    let fee = crate::fee::fee_from_bps_floor(amount, fee_bps);
    token::StellarAssetClient::new(env, token).mint(owner, &amount);
    client.set_fee_config(admin, &FeeConfig { fee_bps });
    let salt = Bytes::from_slice(env, &nonce.to_be_bytes());
    let commitment = client.deposit(token, &amount, owner, &salt, &0, &None, &nonce, &u64::MAX);
    client.withdraw(token, &amount, &commitment, owner, &salt, &nonce, &u64::MAX);
    fee
}

/// Assert that `withdraw_fees` failed with the expected contract error.
///
/// `withdraw_fees` returns `i128`, so the generated `try_` client surfaces the
/// error as `<i128 as TryFromVal<Env, Val>>::Error` (i.e. `soroban_sdk::Error`),
/// unlike unit-returning entry points which use `ConversionError`.
fn assert_withdraw_fees_error(
    result: Result<Result<i128, soroban_sdk::Error>, Result<QuickexError, InvokeError>>,
    expected: QuickexError,
) {
    match result {
        Err(Ok(actual)) => assert_eq!(actual, expected),
        _ => panic!("expected contract error"),
    }
}

#[test]
fn test_full_withdrawal_transfers_all_accrued_fees() {
    let (env, client, admin, token) = setup();
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);

    let fee = accrue_fee(&env, &client, &admin, &token, &owner, 1_000, 1_000, 0);
    assert_eq!(fee, 100);

    // Accrued balance is queryable per asset.
    assert_eq!(client.get_accrued_fees(&token), 100);
    // The fee physically remains in the contract.
    assert_eq!(token_client.balance(&client.address), 100);

    // Full withdrawal transfers everything to the designated recipient.
    let withdrawn = client.withdraw_fees(&admin, &token, &100, &recipient);
    assert_eq!(withdrawn, 100);
    assert_eq!(token_client.balance(&recipient), 100);
    assert_eq!(client.get_accrued_fees(&token), 0);
    assert_eq!(token_client.balance(&client.address), 0);
}

#[test]
fn test_partial_withdrawal() {
    let (env, client, admin, token) = setup();
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);

    accrue_fee(&env, &client, &admin, &token, &owner, 1_000, 1_000, 0);

    // Partial withdrawal #1.
    assert_eq!(client.withdraw_fees(&admin, &token, &40, &recipient), 40);
    assert_eq!(client.get_accrued_fees(&token), 60);
    assert_eq!(token_client.balance(&recipient), 40);
    assert_eq!(token_client.balance(&client.address), 60);

    // Partial withdrawal #2 drains the remainder.
    assert_eq!(client.withdraw_fees(&admin, &token, &60, &recipient), 60);
    assert_eq!(client.get_accrued_fees(&token), 0);
    assert_eq!(token_client.balance(&recipient), 100);
    assert_eq!(token_client.balance(&client.address), 0);
}

#[test]
fn test_over_withdrawal_rejected() {
    let (env, client, admin, token) = setup();
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);

    accrue_fee(&env, &client, &admin, &token, &owner, 1_000, 1_000, 0);

    // Withdrawing more than the accrued balance is rejected.
    assert_withdraw_fees_error(
        client.try_withdraw_fees(&admin, &token, &101, &recipient),
        QuickexError::InsufficientFees,
    );

    // Non-positive amounts are rejected as invalid.
    assert_withdraw_fees_error(
        client.try_withdraw_fees(&admin, &token, &0, &recipient),
        QuickexError::InvalidAmount,
    );
    assert_withdraw_fees_error(
        client.try_withdraw_fees(&admin, &token, &-5, &recipient),
        QuickexError::InvalidAmount,
    );

    // Nothing was transferred and the ledger is untouched.
    assert_eq!(client.get_accrued_fees(&token), 100);
    assert_eq!(token_client.balance(&recipient), 0);
    assert_eq!(token_client.balance(&client.address), 100);
}

#[test]
fn test_unauthorized_caller_rejected() {
    let (env, client, admin, token) = setup();
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);
    let attacker = Address::generate(&env);
    let operator = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);

    accrue_fee(&env, &client, &admin, &token, &owner, 1_000, 1_000, 0);

    // Random caller is rejected.
    assert_withdraw_fees_error(
        client.try_withdraw_fees(&attacker, &token, &100, &recipient),
        QuickexError::InsufficientRole,
    );

    // Operator role is not sufficient — withdrawal is admin-only.
    client.grant_role(&admin, &operator, &Role::Operator);
    assert_withdraw_fees_error(
        client.try_withdraw_fees(&operator, &token, &100, &recipient),
        QuickexError::InsufficientRole,
    );

    // Ledger and balances untouched.
    assert_eq!(client.get_accrued_fees(&token), 100);
    assert_eq!(token_client.balance(&recipient), 0);
}

#[test]
fn test_accounting_invariant_withdrawal_cannot_touch_escrowed_principal() {
    let (env, client, admin, token) = setup();
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);

    // Escrow A settles and accrues its fee in the contract (no collector set).
    accrue_fee(&env, &client, &admin, &token, &owner, 1_000, 1_000, 0);

    // Escrow B stays pending — its principal is live in the contract.
    token::StellarAssetClient::new(&env, &token).mint(&owner, &2_000);
    let salt_b = Bytes::from_slice(&env, b"invariant_salt_b");
    let commitment_b = client.deposit(&token, &2_000, &owner, &salt_b, &0, &None, &1u64, &u64::MAX);

    // Accounting invariant: contract balance == escrowed principal + accrued fees.
    assert_eq!(token_client.balance(&client.address), 2_100);
    assert_eq!(client.get_accrued_fees(&token), 100);

    // Drain the full accrued-fee pool — only fees leave the contract.
    client.withdraw_fees(&admin, &token, &100, &recipient);
    assert_eq!(token_client.balance(&client.address), 2_000);
    assert_eq!(client.get_accrued_fees(&token), 0);

    // Escrowed principal is untouched and still withdrawable by its owner.
    assert_eq!(
        client.get_commitment_state(&commitment_b),
        Some(EscrowStatus::Pending)
    );
    client.withdraw(
        &token,
        &2_000,
        &commitment_b,
        &owner,
        &salt_b,
        &1u64,
        &u64::MAX,
    );
    assert_eq!(token_client.balance(&owner), 2_700); // 900 (net A) + 1800 (net B)
    assert_eq!(client.get_accrued_fees(&token), 200); // B's fee accrues on settle
    assert_eq!(token_client.balance(&client.address), 200);
}

#[test]
fn test_accrued_fees_queryable_per_asset() {
    let (env, client, admin, token_a) = setup();
    let token_b = create_token(&env);
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);

    // No fees accrued yet.
    assert_eq!(client.get_accrued_fees(&token_a), 0);
    assert_eq!(client.get_accrued_fees(&token_b), 0);

    // Different fee rates on different assets accrue independently.
    accrue_fee(&env, &client, &admin, &token_a, &owner, 500, 10_000, 0);
    accrue_fee(&env, &client, &admin, &token_b, &owner, 1_000, 10_000, 1);

    assert_eq!(client.get_accrued_fees(&token_a), 500);
    assert_eq!(client.get_accrued_fees(&token_b), 1_000);

    // Withdrawing one asset leaves the other untouched.
    client.withdraw_fees(&admin, &token_a, &500, &recipient);
    assert_eq!(client.get_accrued_fees(&token_a), 0);
    assert_eq!(client.get_accrued_fees(&token_b), 1_000);
}

#[test]
fn test_fees_withdrawn_event_includes_asset_amount_recipient_actor() {
    let (env, client, admin, token) = setup();
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);

    accrue_fee(&env, &client, &admin, &token, &owner, 1_000, 1_000, 0);
    client.withdraw_fees(&admin, &token, &100, &recipient);

    let all = env.events().all();
    let mut found = false;
    for i in (0..all.len()).rev() {
        let event = all.get(i).unwrap();
        if event.0 != client.address {
            continue;
        }
        let topics = event.1;
        let name: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
        if name != Symbol::new(&env, "FeesWithdrawn") {
            continue;
        }
        found = true;

        // Topics: [TOPIC_ADMIN, FeesWithdrawn, token, recipient].
        let ns: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(ns, Symbol::new(&env, "TOPIC_ADMIN"));
        let topic_token: Address = topics.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic_token, token);
        let topic_recipient: Address = topics.get(3).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic_recipient, recipient);

        // Payload: amount, actor, schema_version, timestamp.
        let data_map: Map<Symbol, Val> = event.2.try_into_val(&env).unwrap();
        let amount: i128 = data_map
            .get(Symbol::new(&env, "amount"))
            .unwrap()
            .try_into_val(&env)
            .unwrap();
        let actor: Address = data_map
            .get(Symbol::new(&env, "actor"))
            .unwrap()
            .try_into_val(&env)
            .unwrap();
        let schema_version: u32 = data_map
            .get(Symbol::new(&env, "schema_version"))
            .unwrap()
            .try_into_val(&env)
            .unwrap();
        assert_eq!(amount, 100);
        assert_eq!(actor, admin);
        assert_eq!(schema_version, EVENT_SCHEMA_VERSION);
        break;
    }
    assert!(found, "FeesWithdrawn event was not emitted");
}

#[test]
fn test_fee_withdrawal_blocked_while_paused() {
    let (env, client, admin, token) = setup();
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);

    accrue_fee(&env, &client, &admin, &token, &owner, 1_000, 1_000, 0);

    client.set_paused(&admin, &true, &0);
    assert_withdraw_fees_error(
        client.try_withdraw_fees(&admin, &token, &100, &recipient),
        QuickexError::ContractPaused,
    );

    // Nothing moved while paused.
    assert_eq!(client.get_accrued_fees(&token), 100);
    assert_eq!(token_client.balance(&recipient), 0);

    // Unpausing restores the ability to withdraw.
    client.set_paused(&admin, &false, &0);
    assert_eq!(client.withdraw_fees(&admin, &token, &100, &recipient), 100);
}

#[test]
fn test_fee_withdrawal_blocked_in_emergency_mode() {
    let (env, client, admin, token) = setup();
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);

    accrue_fee(&env, &client, &admin, &token, &owner, 1_000, 1_000, 0);

    // Withdrawal is not on the emergency allowlist (not a fund-recovery path).
    assert!(!client.is_entry_allowed_in_emergency(&EntryPoint::WithdrawFees));

    client.activate_emergency_mode(&admin);
    assert!(client.is_emergency_mode());
    assert_withdraw_fees_error(
        client.try_withdraw_fees(&admin, &token, &100, &recipient),
        QuickexError::ContractPaused,
    );

    // Fees remain parked in the contract during emergency mode.
    assert_eq!(client.get_accrued_fees(&token), 100);
    assert_eq!(token_client.balance(&recipient), 0);
}

#[test]
fn test_fees_route_to_collector_not_accrued_when_configured() {
    let (env, client, admin, token) = setup();
    let owner = Address::generate(&env);
    let collector = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);

    token::StellarAssetClient::new(&env, &token).mint(&owner, &1_000);
    client.set_fee_config(&admin, &FeeConfig { fee_bps: 1_000 });
    client.set_platform_wallet(&admin, &collector);

    let salt = Bytes::from_slice(&env, b"collector_salt");
    let commitment = client.deposit(&token, &1_000, &owner, &salt, &0, &None, &0u64, &u64::MAX);
    client.withdraw(&token, &1_000, &commitment, &owner, &salt, &0u64, &u64::MAX);

    // Fee went to the collector; nothing accrued.
    assert_eq!(token_client.balance(&collector), 100);
    assert_eq!(client.get_accrued_fees(&token), 0);
    assert_eq!(token_client.balance(&client.address), 0);
}

#[test]
fn test_unrouted_arbiter_share_accrues_when_no_arbiter_provided() {
    let (env, client, admin, token) = setup();
    let owner = Address::generate(&env);
    let token_client = token::Client::new(&env, &token);

    token::StellarAssetClient::new(&env, &token).mint(&owner, &1_000);
    client.set_per_asset_fee(
        &admin,
        &token,
        &PerAssetFeeConfig {
            fee_bps: 1_000,
            arbiter_bps: 2_000,
        },
    );

    let salt = Bytes::from_slice(&env, b"arbiter_share_salt");
    let commitment = client.deposit(&token, &1_000, &owner, &salt, &0, &None, &0u64, &u64::MAX);
    // The withdraw path passes no arbiter: both the arbiter share (20) and the
    // platform share (80, no collector) accrue in the contract.
    client.withdraw(&token, &1_000, &commitment, &owner, &salt, &0u64, &u64::MAX);

    assert_eq!(client.get_accrued_fees(&token), 100);
    assert_eq!(token_client.balance(&client.address), 100);
}
