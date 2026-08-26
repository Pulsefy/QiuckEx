//! Tests for the timelocked two-step admin transfer flow (Issue #870).
//!
//! Covers the acceptance criteria:
//! - accept succeeds after the configured delay has elapsed
//! - accept is rejected when attempted too early
//! - the current admin can cancel a pending proposal
//! - only the proposed address may accept

use crate::{errors::QuickexError, storage::MIN_ADMIN_TRANSFER_DELAY, test_context::TestContext};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{Address, Symbol, TryIntoVal, Val};

/// Returns the topic-1 symbol (the event name) of the most recent event
/// published by `contract_id`, e.g. `"AdminTransferProposed"`.
fn latest_event_name(env: &soroban_sdk::Env, contract_id: &Address) -> Symbol {
    extern crate std;
    let all = env.events().all();
    let expected_str = std::format!("{:?}", contract_id);
    for i in (0..all.len()).rev() {
        let event = all.get(i).unwrap();
        if std::format!("{:?}", event.0) == expected_str {
            let topics = event.1;
            let name_val: Val = topics.get(1).expect("event missing name topic");
            return name_val.try_into_val(env).unwrap();
        }
    }
    panic!("no contract event found for contract id")
}

#[test]
fn accept_succeeds_after_delay_elapses() {
    let ctx = TestContext::with_admin();
    let new_admin = Address::generate(&ctx.env);

    ctx.client
        .propose_admin_transfer(&ctx.admin, &new_admin, &MIN_ADMIN_TRANSFER_DELAY);

    // Too early: accepting right away must fail.
    let early = ctx.client.try_accept_admin_transfer(&new_admin);
    assert_eq!(
        early,
        Err(Ok(QuickexError::AdminTimelockNotElapsed)),
        "accept must fail before the timelock elapses"
    );

    // Advance past the delay, then accept succeeds.
    ctx.advance_time(MIN_ADMIN_TRANSFER_DELAY);
    ctx.client.accept_admin_transfer(&new_admin);

    assert_eq!(ctx.client.get_admin(), Some(new_admin.clone()));
    assert!(ctx.client.get_pending_admin_transfer().is_none());

    // New admin now actually holds admin privileges.
    let another = Address::generate(&ctx.env);
    ctx.client
        .propose_admin_transfer(&new_admin, &another, &MIN_ADMIN_TRANSFER_DELAY);
}

#[test]
fn accept_too_early_is_rejected() {
    let ctx = TestContext::with_admin();
    let new_admin = Address::generate(&ctx.env);

    ctx.client
        .propose_admin_transfer(&ctx.admin, &new_admin, &MIN_ADMIN_TRANSFER_DELAY);

    // Advance, but not far enough.
    ctx.advance_time(MIN_ADMIN_TRANSFER_DELAY - 1);

    let result = ctx.client.try_accept_admin_transfer(&new_admin);
    assert_eq!(result, Err(Ok(QuickexError::AdminTimelockNotElapsed)));

    // Admin is unchanged.
    assert_eq!(ctx.client.get_admin(), Some(ctx.admin.clone()));
}

#[test]
fn current_admin_can_cancel_pending_proposal() {
    let ctx = TestContext::with_admin();
    let new_admin = Address::generate(&ctx.env);

    ctx.client
        .propose_admin_transfer(&ctx.admin, &new_admin, &MIN_ADMIN_TRANSFER_DELAY);
    assert!(ctx.client.get_pending_admin_transfer().is_some());

    ctx.client.cancel_admin_transfer(&ctx.admin);
    assert!(ctx.client.get_pending_admin_transfer().is_none());

    // Advancing time and attempting to accept now fails: nothing pending.
    ctx.advance_time(MIN_ADMIN_TRANSFER_DELAY);
    let result = ctx.client.try_accept_admin_transfer(&new_admin);
    assert_eq!(result, Err(Ok(QuickexError::NoPendingAdminProposal)));

    // Admin never changed.
    assert_eq!(ctx.client.get_admin(), Some(ctx.admin.clone()));
}

#[test]
fn cancel_without_pending_proposal_fails() {
    let ctx = TestContext::with_admin();
    let result = ctx.client.try_cancel_admin_transfer(&ctx.admin);
    assert_eq!(result, Err(Ok(QuickexError::NoPendingAdminProposal)));
}

#[test]
fn wrong_acceptor_is_rejected() {
    let ctx = TestContext::with_admin();
    let new_admin = Address::generate(&ctx.env);
    let impostor = ctx.alice.clone();

    ctx.client
        .propose_admin_transfer(&ctx.admin, &new_admin, &MIN_ADMIN_TRANSFER_DELAY);
    ctx.advance_time(MIN_ADMIN_TRANSFER_DELAY);

    let result = ctx.client.try_accept_admin_transfer(&impostor);
    assert_eq!(result, Err(Ok(QuickexError::InvalidAcceptor)));

    // Admin is unchanged.
    assert_eq!(ctx.client.get_admin(), Some(ctx.admin.clone()));
}

#[test]
fn non_admin_cannot_propose_or_cancel() {
    let ctx = TestContext::with_admin();
    let new_admin = Address::generate(&ctx.env);

    let propose_result =
        ctx.client
            .try_propose_admin_transfer(&ctx.alice, &new_admin, &MIN_ADMIN_TRANSFER_DELAY);
    assert!(propose_result.is_err(), "non-admin must not propose");

    // Set up a legitimate proposal, then confirm a non-admin can't cancel it either.
    ctx.client
        .propose_admin_transfer(&ctx.admin, &new_admin, &MIN_ADMIN_TRANSFER_DELAY);
    let cancel_result = ctx.client.try_cancel_admin_transfer(&ctx.alice);
    assert!(cancel_result.is_err(), "non-admin must not cancel");
}

#[test]
fn delay_below_minimum_is_rejected() {
    let ctx = TestContext::with_admin();
    let new_admin = Address::generate(&ctx.env);

    let result = ctx.client.try_propose_admin_transfer(
        &ctx.admin,
        &new_admin,
        &(MIN_ADMIN_TRANSFER_DELAY - 1),
    );
    assert_eq!(result, Err(Ok(QuickexError::InvalidTimeout)));
    assert!(ctx.client.get_pending_admin_transfer().is_none());
}

#[test]
fn proposing_again_overwrites_previous_proposal() {
    let ctx = TestContext::with_admin();
    let first_candidate = Address::generate(&ctx.env);
    let second_candidate = Address::generate(&ctx.env);

    ctx.client
        .propose_admin_transfer(&ctx.admin, &first_candidate, &MIN_ADMIN_TRANSFER_DELAY);
    ctx.client
        .propose_admin_transfer(&ctx.admin, &second_candidate, &MIN_ADMIN_TRANSFER_DELAY);

    let pending = ctx.client.get_pending_admin_transfer().unwrap();
    assert_eq!(pending.proposed_admin, second_candidate);

    ctx.advance_time(MIN_ADMIN_TRANSFER_DELAY);

    // The old candidate can no longer accept; only the latest proposal counts.
    let stale_accept = ctx.client.try_accept_admin_transfer(&first_candidate);
    assert_eq!(stale_accept, Err(Ok(QuickexError::InvalidAcceptor)));

    ctx.client.accept_admin_transfer(&second_candidate);
    assert_eq!(ctx.client.get_admin(), Some(second_candidate));
}

#[test]
fn proposal_and_acceptance_emit_events() {
    let ctx = TestContext::with_admin();
    let new_admin = Address::generate(&ctx.env);

    ctx.client
        .propose_admin_transfer(&ctx.admin, &new_admin, &MIN_ADMIN_TRANSFER_DELAY);
    assert_eq!(
        latest_event_name(&ctx.env, &ctx.client.address),
        Symbol::new(&ctx.env, "AdminTransferProposed"),
        "propose_admin_transfer must emit AdminTransferProposed"
    );

    ctx.advance_time(MIN_ADMIN_TRANSFER_DELAY);

    ctx.client.accept_admin_transfer(&new_admin);
    // accept_admin_transfer emits AdminTransferAccepted followed by the
    // general-purpose AdminChanged event; the latest one is AdminChanged.
    assert_eq!(
        latest_event_name(&ctx.env, &ctx.client.address),
        Symbol::new(&ctx.env, "AdminChanged"),
        "accept_admin_transfer must emit an event"
    );
}

#[test]
fn cancellation_emits_event() {
    let ctx = TestContext::with_admin();
    let new_admin = Address::generate(&ctx.env);

    ctx.client
        .propose_admin_transfer(&ctx.admin, &new_admin, &MIN_ADMIN_TRANSFER_DELAY);

    ctx.client.cancel_admin_transfer(&ctx.admin);
    assert_eq!(
        latest_event_name(&ctx.env, &ctx.client.address),
        Symbol::new(&ctx.env, "AdminTransferCancelled"),
        "cancel_admin_transfer must emit AdminTransferCancelled"
    );
}
