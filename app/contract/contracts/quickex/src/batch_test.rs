//! # Batch escrow integration tests — Issue #1007
//!
//! These tests drive `batch_create` / `batch_release` / `batch_refund` through
//! the **public** `QuickexContractClient`, never through `env.as_contract`, so
//! they exercise the same path a real client takes: the generated client, the
//! `#[contractimpl]` dispatch, the pause gate, the reentrancy guard, and the
//! token contract.
//!
//! The properties asserted here are the ones the module previously violated:
//!
//! 1. **Funds actually move.** `batch_create` transfers each item's `amount`
//!    from the item's owner into the contract; `batch_release` pays the
//!    recipient; `batch_refund` returns funds to the owner. Balances are
//!    asserted before and after every call.
//! 2. **Escrow ids are derived, not caller-supplied.** The returned commitment
//!    verifies against `(owner, amount, salt)` for every created item.
//! 3. **Pause and emergency gating matches the single-item flows.**
//! 4. **Replay protection is real and domain-separated per entry point.**

use crate::{
    assert_helpers::{
        assert_escrow_not_found, assert_escrow_pending, assert_escrow_refunded,
        assert_escrow_spent, assert_qx_err,
    },
    batch::{BatchCreateItem, BatchItemResult, BatchRefundItem, BatchReleaseItem, MAX_BATCH_SIZE},
    errors::QuickexError,
    pause_policy::EntryPoint,
    storage::PauseFlag,
    test_context::TestContext,
    types::EscrowStatus,
};

use soroban_sdk::{testutils::Ledger, token, Address, Bytes, BytesN, Vec};

extern crate std;
use std::sync::atomic::{AtomicU64, Ordering};

const AMOUNT: i128 = 1_000;
const TIMEOUT: u64 = 3_600;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Nonces are consumed globally per `(signer, action)`, so every item across
/// every call in a test needs a distinct value. A shared counter keeps the
/// fixtures readable while guaranteeing uniqueness (tests run in parallel
/// threads, so it has to be process-wide rather than a local `Cell`).
static NEXT_NONCE: AtomicU64 = AtomicU64::new(1);

fn next_nonce() -> u64 {
    NEXT_NONCE.fetch_add(1, Ordering::Relaxed)
}

/// A context with a zero-fee config, so balance arithmetic is exact.
fn setup() -> TestContext<'static> {
    TestContext::with_fees(0)
}

fn salt_for(ctx: &TestContext, tag: u8) -> Bytes {
    Bytes::from_slice(&ctx.env, &[tag])
}

fn create_item(
    ctx: &TestContext,
    tag: u8,
    owner: &Address,
    amount: i128,
    timeout_secs: u64,
) -> BatchCreateItem {
    BatchCreateItem {
        token: ctx.token.clone(),
        amount,
        owner: owner.clone(),
        salt: salt_for(ctx, tag),
        timeout_secs,
        arbiter: None,
        nonce: next_nonce(),
        valid_until: u64::MAX,
    }
}

/// A release item. `to` is both the commitment prover and the payout
/// recipient, exactly as in `withdraw` — so it must be the address that
/// created the commitment (i.e. the escrow's owner).
fn release_item(ctx: &TestContext, tag: u8, to: &Address, amount: i128) -> BatchReleaseItem {
    BatchReleaseItem {
        to: to.clone(),
        amount,
        salt: salt_for(ctx, tag),
        nonce: next_nonce(),
        valid_until: u64::MAX,
    }
}

fn refund_item(commitment: &BytesN<32>) -> BatchRefundItem {
    BatchRefundItem {
        commitment: commitment.clone(),
        nonce: next_nonce(),
        valid_until: u64::MAX,
    }
}

fn balance(ctx: &TestContext, address: &Address) -> i128 {
    token::Client::new(&ctx.env, &ctx.token).balance(address)
}

fn assert_success(result: &BatchItemResult, index: u32) {
    assert!(
        result.success,
        "item {index} should have succeeded, but failed with error_code {}",
        result.error_code
    );
    assert_eq!(
        result.error_code, 0,
        "successful item must carry error_code 0"
    );
    assert_eq!(result.index, index, "result must be in submission order");
}

fn assert_failure(result: &BatchItemResult, index: u32, expected: QuickexError) {
    assert!(
        !result.success,
        "item {index} should have failed with {expected:?}"
    );
    assert_eq!(
        result.error_code, expected as u32,
        "item {index} should report {expected:?} as its error_code"
    );
    assert_eq!(result.index, index, "result must be in submission order");
}

/// Run a `batch_create` and return the per-item results.
fn do_create(ctx: &TestContext, items: Vec<BatchCreateItem>) -> Vec<BatchItemResult> {
    ctx.client.batch_create(&items)
}

/// Run a `batch_create` of `count` identical-shape items for one owner, all
/// with `timeout_secs`, and return the derived commitments.
fn fund(
    ctx: &TestContext,
    owner: &Address,
    count: u8,
    first_tag: u8,
    amount: i128,
    timeout_secs: u64,
) -> Vec<BytesN<32>> {
    let mut items: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    for offset in 0..count {
        items.push_back(create_item(
            ctx,
            first_tag + offset,
            owner,
            amount,
            timeout_secs,
        ));
    }
    let results = do_create(ctx, items);
    let mut commitments = Vec::new(&ctx.env);
    for i in 0..count as u32 {
        assert_success(&results.get(i).unwrap(), i);
        commitments.push_back(results.get(i).unwrap().commitment.unwrap());
    }
    commitments
}

// ---------------------------------------------------------------------------
// batch_create — funds actually move
// ---------------------------------------------------------------------------

/// The core regression: `batch_create` must pull real tokens out of the owner's
/// wallet and into the contract, once per successful item.
#[test]
fn batch_create_transfers_funds_into_the_contract() {
    let ctx = setup();
    let count = 5u8;
    let total = AMOUNT * count as i128;

    ctx.mint(&ctx.alice, total);
    assert_eq!(
        balance(&ctx, &ctx.alice),
        total,
        "owner starts fully funded"
    );
    assert_eq!(balance(&ctx, &ctx.client.address), 0);

    let commitments = fund(&ctx, &ctx.alice, count, 0, AMOUNT, 0);

    // Balances moved by exactly the batch total.
    assert_eq!(
        balance(&ctx, &ctx.alice),
        0,
        "owner must be debited the full batch total"
    );
    assert_eq!(
        balance(&ctx, &ctx.client.address),
        total,
        "contract must hold the full batch total"
    );

    // Every item is a real, derived, pending escrow.
    for offset in 0..count {
        let commitment = commitments.get(offset as u32).unwrap();
        assert_escrow_pending(&ctx.client, &commitment);
        assert_eq!(
            ctx.client.get_commitment_state(&commitment),
            Some(EscrowStatus::Pending)
        );
        // The id is the commitment over (owner, amount, salt) — not a
        // caller-chosen key.
        assert_eq!(commitment, ctx.commitment(&ctx.alice, AMOUNT, &[offset]));
        assert!(ctx.client.verify_amount_commitment(
            &commitment,
            &ctx.alice,
            &AMOUNT,
            &salt_for(&ctx, offset)
        ));
    }
}

/// A single batch may fund items for several different owners; each item is
/// debited from its own `owner`, not from one batch-wide caller.
#[test]
fn batch_create_debits_each_items_own_owner() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);
    ctx.mint(&ctx.bob, AMOUNT * 2);

    let mut items: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    items.push_back(create_item(&ctx, 1, &ctx.alice, AMOUNT, 0));
    items.push_back(create_item(&ctx, 2, &ctx.bob, AMOUNT, 0));
    items.push_back(create_item(&ctx, 3, &ctx.bob, AMOUNT, 0));

    let results = do_create(&ctx, items);
    for i in 0..3u32 {
        assert_success(&results.get(i).unwrap(), i);
    }

    assert_eq!(balance(&ctx, &ctx.alice), 0, "alice funded one item");
    assert_eq!(balance(&ctx, &ctx.bob), 0, "bob funded two items");
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT * 3);
}

/// Many items for the *same* owner in one batch.
///
/// This is the case that a naive per-item `require_auth` implementation cannot
/// handle: Soroban authorizes an `(address, contract)` pair only once per
/// invocation frame and fails the second attempt with `Auth(ExistingValue)`.
/// The entry point deduplicates authorization, so every item still runs.
#[test]
fn batch_create_authorizes_a_repeated_owner_once() {
    let ctx = setup();
    let count = 8u8;
    ctx.mint(&ctx.alice, AMOUNT * count as i128);

    let commitments = fund(&ctx, &ctx.alice, count, 0, AMOUNT, 0);

    assert_eq!(balance(&ctx, &ctx.alice), 0);
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT * count as i128);
    assert_eq!(commitments.len(), count as u32);
}

/// The full lifecycle through the public client: create → release, with the
/// token balance walking owner → contract → owner.
#[test]
fn batch_create_then_batch_release_returns_funds_to_the_recipient() {
    let ctx = setup();
    let count = 4u8;
    let total = AMOUNT * count as i128;

    ctx.mint(&ctx.alice, total);
    assert_eq!(balance(&ctx, &ctx.bob), 0);

    let commitments = fund(&ctx, &ctx.alice, count, 0, AMOUNT, TIMEOUT);
    assert_eq!(balance(&ctx, &ctx.client.address), total);
    assert_eq!(balance(&ctx, &ctx.alice), 0, "escrow is holding the funds");

    let mut releases: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    for offset in 0..count {
        releases.push_back(release_item(&ctx, offset, &ctx.alice, AMOUNT));
    }
    let release_results = ctx.client.batch_release(&releases);

    for i in 0..count as u32 {
        assert_success(&release_results.get(i).unwrap(), i);
        let commitment = commitments.get(i).unwrap();
        assert_escrow_spent(&ctx.client, &commitment);
        // The release echoed the same derived commitment the create produced.
        assert_eq!(release_results.get(i).unwrap().commitment, Some(commitment));
    }

    assert_eq!(
        balance(&ctx, &ctx.alice),
        total,
        "recipient must receive the full escrowed total (zero-fee config)"
    );
    assert_eq!(
        balance(&ctx, &ctx.client.address),
        0,
        "contract must be drained after a full release"
    );
}

/// Release routes through the same fee-aware payout as `withdraw`: with a
/// non-zero fee the recipient nets out the fee and the platform wallet keeps it.
#[test]
fn batch_release_routes_fees_like_single_item_withdraw() {
    let ctx = TestContext::with_fees(250); // 2.5%
    let count = 2u8;
    let total = AMOUNT * count as i128;

    ctx.mint(&ctx.alice, total);
    let commitments = fund(&ctx, &ctx.alice, count, 0, AMOUNT, TIMEOUT);
    assert_eq!(balance(&ctx, &ctx.client.address), total);

    let mut releases: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    for offset in 0..count {
        releases.push_back(release_item(&ctx, offset, &ctx.alice, AMOUNT));
    }
    let results = ctx.client.batch_release(&releases);
    for i in 0..count as u32 {
        assert_success(&results.get(i).unwrap(), i);
    }

    // 2.5% of 2000 = 50 fee, 1950 to the recipient.
    let expected_fee = (total * 250) / 10_000;
    assert_eq!(expected_fee, 50);
    assert_eq!(balance(&ctx, &ctx.alice), total - expected_fee);
    assert_eq!(
        balance(&ctx, &ctx.platform_wallet),
        expected_fee,
        "platform wallet receives the fee"
    );
    assert_eq!(balance(&ctx, &ctx.client.address), 0);

    for i in 0..count as u32 {
        assert_escrow_spent(&ctx.client, &commitments.get(i).unwrap());
    }
}

// ---------------------------------------------------------------------------
// batch_create — validation and limits
// ---------------------------------------------------------------------------

/// A batch of `MAX_BATCH_SIZE + 1` is rejected up front, and rejection has no
/// side effects at all — not a single token moves.
#[test]
fn batch_create_over_limit_is_rejected_with_no_side_effects() {
    let ctx = setup();
    let total = AMOUNT * (MAX_BATCH_SIZE as i128 + 1);
    ctx.mint(&ctx.alice, total);

    let mut items: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    for tag in 0..=MAX_BATCH_SIZE {
        items.push_back(create_item(&ctx, tag as u8, &ctx.alice, AMOUNT, 0));
    }

    assert_qx_err(
        ctx.client.try_batch_create(&items),
        QuickexError::BatchSizeExceeded,
    );

    assert_eq!(
        balance(&ctx, &ctx.alice),
        total,
        "a rejected batch must not move any tokens"
    );
    assert_eq!(balance(&ctx, &ctx.client.address), 0);

    for tag in 0..=MAX_BATCH_SIZE {
        assert_escrow_not_found(
            &ctx.client,
            &ctx.commitment(&ctx.alice, AMOUNT, &[tag as u8]),
        );
    }
}

/// A batch of exactly `MAX_BATCH_SIZE` is accepted.
#[test]
fn batch_create_at_limit_succeeds_and_moves_every_amount() {
    let ctx = setup();
    let count = MAX_BATCH_SIZE;
    let total = AMOUNT * count as i128;

    ctx.mint(&ctx.alice, total);
    let mut items: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    for tag in 0..count {
        items.push_back(create_item(&ctx, tag as u8, &ctx.alice, AMOUNT, 0));
    }

    let results = do_create(&ctx, items);
    assert_eq!(results.len(), count);
    for tag in 0..count {
        assert_success(&results.get(tag).unwrap(), tag);
    }
    assert_eq!(balance(&ctx, &ctx.alice), 0);
    assert_eq!(balance(&ctx, &ctx.client.address), total);
}

/// Per-item validation failures are reported in the returned vector and do not
/// stop the rest of the batch. Only the *valid* items move tokens.
#[test]
fn batch_create_reports_per_item_failures_and_keeps_going() {
    let ctx = setup();
    // Enough for the three valid items only.
    ctx.mint(&ctx.alice, AMOUNT * 3);

    let mut items: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    items.push_back(create_item(&ctx, 0, &ctx.alice, AMOUNT, 0)); // valid
    items.push_back(create_item(&ctx, 1, &ctx.alice, 0, 0)); // zero amount
    items.push_back(create_item(&ctx, 2, &ctx.alice, -5, 0)); // negative amount
    items.push_back(create_item(&ctx, 3, &ctx.alice, AMOUNT, 0)); // valid
    items.push_back(create_item(&ctx, 4, &ctx.alice, AMOUNT, u64::MAX)); // bad timeout
    items.push_back(create_item(&ctx, 5, &ctx.alice, AMOUNT, 0)); // valid

    let results = do_create(&ctx, items);
    assert_eq!(results.len(), 6);

    assert_success(&results.get(0).unwrap(), 0);
    assert_failure(&results.get(1).unwrap(), 1, QuickexError::InvalidAmount);
    assert_failure(&results.get(2).unwrap(), 2, QuickexError::InvalidAmount);
    assert_success(&results.get(3).unwrap(), 3);
    assert_failure(&results.get(4).unwrap(), 4, QuickexError::InvalidTimeout);
    assert_success(&results.get(5).unwrap(), 5);

    // Failed items expose no commitment and wrote no escrow.
    for tag in [1u8, 2, 4] {
        assert_eq!(
            results.get(tag as u32).unwrap().commitment,
            None,
            "item {tag} was rejected before derivation, so it must expose no commitment"
        );
        assert_escrow_not_found(&ctx.client, &ctx.commitment(&ctx.alice, AMOUNT, &[tag]));
    }

    // Exactly three transfers happened.
    assert_eq!(balance(&ctx, &ctx.alice), 0);
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT * 3);
}

/// Re-submitting an identical create is idempotent through the escrow-id
/// mapping, and does not take a second transfer.
#[test]
fn batch_create_duplicate_payload_is_idempotent() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT * 2);

    let first = fund(&ctx, &ctx.alice, 1, 7, AMOUNT, TIMEOUT);
    let commitment = first.get(0).unwrap();
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT);

    // Same payload, fresh nonce: the escrow-id mapping short-circuits, so the
    // contract reports the original commitment and takes no second transfer.
    let mut again: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    again.push_back(create_item(&ctx, 7, &ctx.alice, AMOUNT, TIMEOUT));
    let retried = do_create(&ctx, again);

    assert_success(&retried.get(0).unwrap(), 0);
    assert_eq!(retried.get(0).unwrap().commitment, Some(commitment.clone()));
    assert_eq!(
        balance(&ctx, &ctx.client.address),
        AMOUNT,
        "an idempotent re-submit must not take a second transfer"
    );

    // And the escrow is still withdrawable exactly once.
    let mut releases: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    releases.push_back(release_item(&ctx, 7, &ctx.alice, AMOUNT));
    assert_success(&ctx.client.batch_release(&releases).get(0).unwrap(), 0);
    assert_eq!(
        balance(&ctx, &ctx.alice),
        AMOUNT * 2,
        "the full minted balance returns to the owner after the release"
    );
    assert_eq!(balance(&ctx, &ctx.client.address), 0);
}

// ---------------------------------------------------------------------------
// Replay protection
// ---------------------------------------------------------------------------

/// Reusing a create nonce is rejected per item, and moves no tokens.
#[test]
fn batch_create_rejects_replayed_nonce() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT * 2);

    let mut items: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    items.push_back(create_item(&ctx, 0, &ctx.alice, AMOUNT, 0));
    items.push_back(create_item(&ctx, 1, &ctx.alice, AMOUNT, 0));
    let first = do_create(&ctx, items.clone());
    assert_success(&first.get(0).unwrap(), 0);
    assert_success(&first.get(1).unwrap(), 1);
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT * 2);

    // Replay the exact same vector.
    let replay = do_create(&ctx, items);
    assert_failure(&replay.get(0).unwrap(), 0, QuickexError::NonceAlreadyUsed);
    assert_failure(&replay.get(1).unwrap(), 1, QuickexError::NonceAlreadyUsed);
    assert_eq!(
        balance(&ctx, &ctx.client.address),
        AMOUNT * 2,
        "a replayed nonce must not move tokens"
    );
}

/// Domain separation: a nonce consumed by the single-item `deposit` is *not*
/// consumed for `batch_create`, and vice versa. This is what stops a signature
/// minted for one flow being replayed on the other.
#[test]
fn batch_action_types_are_domain_separated_from_single_item_flows() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT * 4);
    let shared = 424_242u64;
    let shared2 = 424_243u64;

    // Burn `shared` on the single-item `deposit` path.
    ctx.client.deposit(
        &ctx.token,
        &AMOUNT,
        &ctx.alice,
        &salt_for(&ctx, 0),
        &0,
        &None,
        &shared,
        &u64::MAX,
    );

    // The same nonce value on `batch_create` is still fresh.
    let mut items: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    items.push_back(BatchCreateItem {
        nonce: shared,
        ..create_item(&ctx, 1, &ctx.alice, AMOUNT, 0)
    });
    assert_success(&do_create(&ctx, items).get(0).unwrap(), 0);
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT * 2);

    // And the reverse: a nonce burned on `batch_create` is not burned on
    // `deposit`.
    let mut more: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    more.push_back(BatchCreateItem {
        nonce: shared2,
        ..create_item(&ctx, 2, &ctx.alice, AMOUNT, 0)
    });
    assert_success(&do_create(&ctx, more).get(0).unwrap(), 0);
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT * 3);

    ctx.client.deposit(
        &ctx.token,
        &AMOUNT,
        &ctx.alice,
        &salt_for(&ctx, 3),
        &0,
        &None,
        &shared2,
        &u64::MAX,
    );
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT * 4);
}

/// A release nonce is also domain-separated from a create nonce for the same
/// owner, so the two flows cannot cross-replay.
#[test]
fn batch_release_nonce_is_separate_from_batch_create_nonce() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);
    let shared = 515_151u64;

    let mut creates: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    creates.push_back(BatchCreateItem {
        nonce: shared,
        ..create_item(&ctx, 0, &ctx.alice, AMOUNT, TIMEOUT)
    });
    assert_success(&do_create(&ctx, creates).get(0).unwrap(), 0);

    // Same nonce, different action: allowed.
    let mut releases: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    releases.push_back(BatchReleaseItem {
        nonce: shared,
        ..release_item(&ctx, 0, &ctx.alice, AMOUNT)
    });
    assert_success(&ctx.client.batch_release(&releases).get(0).unwrap(), 0);
    assert_eq!(balance(&ctx, &ctx.alice), AMOUNT);
}

/// An expired `valid_until` is rejected per item, exactly as in a single call.
#[test]
fn batch_create_rejects_expired_valid_until() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);
    ctx.env.ledger().set_timestamp(1_000);

    let mut items: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    items.push_back(BatchCreateItem {
        valid_until: 999,
        ..create_item(&ctx, 0, &ctx.alice, AMOUNT, 0)
    });

    let results = do_create(&ctx, items);
    assert_failure(&results.get(0).unwrap(), 0, QuickexError::SignatureExpired);
    assert_eq!(balance(&ctx, &ctx.client.address), 0);
}

// ---------------------------------------------------------------------------
// batch_release — invariants
// ---------------------------------------------------------------------------

/// Time-lock parity (INV-1): an expired escrow cannot be released.
#[test]
fn batch_release_rejects_expired_escrow() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);

    let commitments = fund(&ctx, &ctx.alice, 1, 0, AMOUNT, TIMEOUT);
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT);

    ctx.advance_time(TIMEOUT);

    let mut releases: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    releases.push_back(release_item(&ctx, 0, &ctx.alice, AMOUNT));
    let results = ctx.client.batch_release(&releases);

    assert_failure(&results.get(0).unwrap(), 0, QuickexError::EscrowExpired);
    assert_eq!(
        balance(&ctx, &ctx.alice),
        0,
        "no payout on an expired escrow"
    );
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT);
    assert_escrow_pending(&ctx.client, &commitments.get(0).unwrap());
}

/// A non-expiring escrow (`timeout_secs == 0`) is never expired (INV-1/INV-2).
#[test]
fn batch_release_treats_zero_timeout_as_non_expiring() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);

    let commitments = fund(&ctx, &ctx.alice, 1, 0, AMOUNT, 0);
    ctx.advance_time(TIMEOUT * 10);

    let mut releases: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    releases.push_back(release_item(&ctx, 0, &ctx.alice, AMOUNT));
    assert_success(&ctx.client.batch_release(&releases).get(0).unwrap(), 0);
    assert_escrow_spent(&ctx.client, &commitments.get(0).unwrap());
    assert_eq!(balance(&ctx, &ctx.alice), AMOUNT);
}

/// Terminal-state parity (INV-5): releasing twice fails, and the second
/// release pays nothing.
#[test]
fn batch_release_rejects_already_spent_escrow() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);

    let commitments = fund(&ctx, &ctx.alice, 1, 0, AMOUNT, TIMEOUT);

    let mut releases: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    releases.push_back(release_item(&ctx, 0, &ctx.alice, AMOUNT));
    assert_success(&ctx.client.batch_release(&releases).get(0).unwrap(), 0);
    assert_eq!(balance(&ctx, &ctx.alice), AMOUNT);

    let mut again: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    again.push_back(release_item(&ctx, 0, &ctx.alice, AMOUNT));
    let results = ctx.client.batch_release(&again);
    assert_failure(&results.get(0).unwrap(), 0, QuickexError::AlreadySpent);
    assert_eq!(balance(&ctx, &ctx.alice), AMOUNT, "no second payout");
    assert_escrow_spent(&ctx.client, &commitments.get(0).unwrap());
}

/// A release cannot reach another address's escrow. `to` is the commitment
/// prover as well as the payout target, so a different address recomputes a
/// different commitment and finds nothing.
///
/// This is the property that makes it safe to expose a batch release at all:
/// escrows are addressed by a hash of `(owner, amount, salt)`, never by a
/// caller-supplied key, so no batch item can name an escrow it does not own.
#[test]
fn batch_release_cannot_reach_another_owners_escrow() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);
    ctx.mint(&ctx.bob, AMOUNT * 10);

    let commitments = fund(&ctx, &ctx.alice, 1, 0, AMOUNT, TIMEOUT);
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT);

    // Bob presents alice's salt and amount, but as himself.
    let mut releases: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    releases.push_back(release_item(&ctx, 0, &ctx.bob, AMOUNT));
    let results = ctx.client.batch_release(&releases);

    assert_failure(
        &results.get(0).unwrap(),
        0,
        QuickexError::CommitmentNotFound,
    );
    assert_eq!(
        balance(&ctx, &ctx.bob),
        AMOUNT * 10,
        "bob must not be able to drain alice's escrow"
    );
    assert_escrow_pending(&ctx.client, &commitments.get(0).unwrap());
}

/// An unknown escrow is reported per item.
#[test]
fn batch_release_rejects_unknown_escrow() {
    let ctx = setup();
    let mut releases: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    releases.push_back(release_item(&ctx, 9, &ctx.alice, AMOUNT));
    let results = ctx.client.batch_release(&releases);
    assert_failure(
        &results.get(0).unwrap(),
        0,
        QuickexError::CommitmentNotFound,
    );
    assert_eq!(balance(&ctx, &ctx.alice), 0);
}

#[test]
fn batch_release_over_limit_is_rejected() {
    let ctx = setup();
    let mut items: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    for tag in 0..=MAX_BATCH_SIZE {
        items.push_back(release_item(&ctx, tag as u8, &ctx.alice, AMOUNT));
    }
    assert_qx_err(
        ctx.client.try_batch_release(&items),
        QuickexError::BatchSizeExceeded,
    );
}

// ---------------------------------------------------------------------------
// batch_refund — funds go back to the owner
// ---------------------------------------------------------------------------

/// The core refund regression: `batch_refund` must actually transfer the
/// escrowed amount from the contract back to the owner.
#[test]
fn batch_refund_returns_funds_to_the_owner() {
    let ctx = setup();
    let count = 3u8;
    let total = AMOUNT * count as i128;
    ctx.mint(&ctx.alice, total);

    let commitments = fund(&ctx, &ctx.alice, count, 0, AMOUNT, TIMEOUT);
    assert_eq!(balance(&ctx, &ctx.alice), 0);
    assert_eq!(balance(&ctx, &ctx.client.address), total);

    ctx.advance_time(TIMEOUT);

    let mut refunds: Vec<BatchRefundItem> = Vec::new(&ctx.env);
    for i in 0..count as u32 {
        refunds.push_back(refund_item(&commitments.get(i).unwrap()));
    }
    let results = ctx.client.batch_refund(&ctx.alice, &refunds);
    assert_eq!(results.len(), count as u32);

    for i in 0..count as u32 {
        assert_success(&results.get(i).unwrap(), i);
    }

    assert_eq!(
        balance(&ctx, &ctx.alice),
        total,
        "owner must get every escrowed amount back"
    );
    assert_eq!(balance(&ctx, &ctx.client.address), 0);
    for i in 0..count as u32 {
        assert_escrow_refunded(&ctx.client, &commitments.get(i).unwrap());
    }
}

/// Time-lock parity (INV-2): a refund before expiry is rejected and moves
/// nothing.
#[test]
fn batch_refund_rejects_escrow_that_has_not_expired() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);

    let commitments = fund(&ctx, &ctx.alice, 1, 0, AMOUNT, TIMEOUT);

    let mut refunds: Vec<BatchRefundItem> = Vec::new(&ctx.env);
    refunds.push_back(refund_item(&commitments.get(0).unwrap()));
    let results = ctx.client.batch_refund(&ctx.alice, &refunds);

    assert_failure(&results.get(0).unwrap(), 0, QuickexError::EscrowNotExpired);
    assert_eq!(balance(&ctx, &ctx.alice), 0, "no refund before expiry");
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT);
}

/// A refund always pays the escrow's recorded owner. A non-owner caller cannot
/// redirect the funds.
#[test]
fn batch_refund_rejects_non_owner_caller() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);

    let commitments = fund(&ctx, &ctx.alice, 1, 0, AMOUNT, TIMEOUT);
    ctx.advance_time(TIMEOUT);

    let mut refunds: Vec<BatchRefundItem> = Vec::new(&ctx.env);
    refunds.push_back(refund_item(&commitments.get(0).unwrap()));
    let results = ctx.client.batch_refund(&ctx.bob, &refunds);

    assert_failure(&results.get(0).unwrap(), 0, QuickexError::InvalidOwner);
    assert_eq!(balance(&ctx, &ctx.bob), 0, "a non-owner must never be paid");
    assert_eq!(balance(&ctx, &ctx.alice), 0);
    assert_eq!(
        balance(&ctx, &ctx.client.address),
        AMOUNT,
        "funds stay escrowed after a rejected refund"
    );
}

#[test]
fn batch_refund_rejects_already_terminal_escrow() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);

    let commitments = fund(&ctx, &ctx.alice, 1, 0, AMOUNT, TIMEOUT);
    let commitment = commitments.get(0).unwrap();
    ctx.advance_time(TIMEOUT);

    let mut refunds: Vec<BatchRefundItem> = Vec::new(&ctx.env);
    refunds.push_back(refund_item(&commitment));
    assert_success(
        &ctx.client
            .batch_refund(&ctx.alice, &refunds)
            .get(0)
            .unwrap(),
        0,
    );
    assert_eq!(balance(&ctx, &ctx.alice), AMOUNT);

    let mut again: Vec<BatchRefundItem> = Vec::new(&ctx.env);
    again.push_back(refund_item(&commitment));
    let results = ctx.client.batch_refund(&ctx.alice, &again);
    assert_failure(&results.get(0).unwrap(), 0, QuickexError::AlreadySpent);
    assert_eq!(balance(&ctx, &ctx.alice), AMOUNT, "no double refund");
    assert_escrow_refunded(&ctx.client, &commitment);
}

#[test]
fn batch_refund_over_limit_is_rejected() {
    let ctx = setup();
    let commitment = BytesN::from_array(&ctx.env, &[1u8; 32]);
    let mut items: Vec<BatchRefundItem> = Vec::new(&ctx.env);
    for _ in 0..=MAX_BATCH_SIZE {
        items.push_back(refund_item(&commitment));
    }
    assert_qx_err(
        ctx.client.try_batch_refund(&ctx.alice, &items),
        QuickexError::BatchSizeExceeded,
    );
}

/// Mixed success/failure refund batch: valid items are refunded, unexpired and
/// unknown ones are reported per item. The failed items still echo their input
/// commitment so the caller can correlate them.
#[test]
fn batch_refund_reports_per_item_failures() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT * 2);

    let mut creates: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    creates.push_back(create_item(&ctx, 0, &ctx.alice, AMOUNT, TIMEOUT));
    creates.push_back(create_item(&ctx, 1, &ctx.alice, AMOUNT, TIMEOUT * 2));
    let created = do_create(&ctx, creates);
    let c0 = created.get(0).unwrap().commitment.unwrap();
    let c1 = created.get(1).unwrap().commitment.unwrap();

    // Only item 0 has expired.
    ctx.advance_time(TIMEOUT + 1);

    let unknown = BytesN::from_array(&ctx.env, &[7u8; 32]);
    let mut refunds: Vec<BatchRefundItem> = Vec::new(&ctx.env);
    refunds.push_back(refund_item(&c0));
    refunds.push_back(refund_item(&c1));
    refunds.push_back(refund_item(&unknown));

    let results = ctx.client.batch_refund(&ctx.alice, &refunds);
    assert_success(&results.get(0).unwrap(), 0);
    assert_failure(&results.get(1).unwrap(), 1, QuickexError::EscrowNotExpired);
    assert_failure(
        &results.get(2).unwrap(),
        2,
        QuickexError::CommitmentNotFound,
    );

    assert_eq!(
        balance(&ctx, &ctx.alice),
        AMOUNT,
        "only the expired escrow was refunded"
    );
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT);
    assert_eq!(
        results.get(2).unwrap().commitment,
        Some(unknown),
        "a failed refund still echoes its input commitment"
    );
    assert_escrow_refunded(&ctx.client, &c0);
    assert_escrow_pending(&ctx.client, &c1);
}

// ---------------------------------------------------------------------------
// Pause policy / emergency mode parity
// ---------------------------------------------------------------------------

/// The deposit feature flag must block `batch_create` exactly as it blocks
/// `deposit` — the batch path is not a way around a granular pause.
#[test]
fn batch_create_respects_the_deposit_feature_pause() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);

    let mut items: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    items.push_back(create_item(&ctx, 0, &ctx.alice, AMOUNT, 0));

    ctx.client
        .pause_features(&ctx.admin, &PauseFlag::Deposit.bits(), &0);

    // The single-item deposit is blocked...
    assert_qx_err(
        ctx.client.try_deposit(
            &ctx.token,
            &AMOUNT,
            &ctx.alice,
            &salt_for(&ctx, 99),
            &0,
            &None,
            &next_nonce(),
            &u64::MAX,
        ),
        QuickexError::OperationPaused,
    );
    // ...and so is the batch path.
    assert_qx_err(
        ctx.client.try_batch_create(&items),
        QuickexError::OperationPaused,
    );
    assert_eq!(balance(&ctx, &ctx.client.address), 0);
    assert_eq!(balance(&ctx, &ctx.alice), AMOUNT);
}

/// The withdrawal feature flag must block `batch_release`.
#[test]
fn batch_release_respects_the_withdrawal_feature_pause() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);

    let commitments = fund(&ctx, &ctx.alice, 1, 0, AMOUNT, TIMEOUT);

    let mut releases: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    releases.push_back(release_item(&ctx, 0, &ctx.alice, AMOUNT));

    ctx.client
        .pause_features(&ctx.admin, &PauseFlag::Withdrawal.bits(), &0);

    assert_qx_err(
        ctx.client.try_batch_release(&releases),
        QuickexError::OperationPaused,
    );
    assert_eq!(balance(&ctx, &ctx.alice), 0);
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT);
    assert_escrow_pending(&ctx.client, &commitments.get(0).unwrap());
}

/// The refund feature flag must block `batch_refund`.
#[test]
fn batch_refund_respects_the_refund_feature_pause() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);

    let commitments = fund(&ctx, &ctx.alice, 1, 0, AMOUNT, TIMEOUT);
    ctx.advance_time(TIMEOUT);

    let mut refunds: Vec<BatchRefundItem> = Vec::new(&ctx.env);
    refunds.push_back(refund_item(&commitments.get(0).unwrap()));

    ctx.client
        .pause_features(&ctx.admin, &PauseFlag::Refund.bits(), &0);

    assert_qx_err(
        ctx.client.try_batch_refund(&ctx.alice, &refunds),
        QuickexError::OperationPaused,
    );
    assert_eq!(balance(&ctx, &ctx.alice), 0);
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT);
}

/// A global pause blocks all three batch entry points and moves no funds.
#[test]
fn all_batch_entrypoints_respect_the_global_pause() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT);

    let commitments = fund(&ctx, &ctx.alice, 1, 0, AMOUNT, TIMEOUT);
    ctx.advance_time(TIMEOUT);

    let mut creates: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    creates.push_back(create_item(&ctx, 1, &ctx.alice, AMOUNT, TIMEOUT));
    let mut releases: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    releases.push_back(release_item(&ctx, 0, &ctx.alice, AMOUNT));
    let mut refunds: Vec<BatchRefundItem> = Vec::new(&ctx.env);
    refunds.push_back(refund_item(&commitments.get(0).unwrap()));

    ctx.client.set_paused(&ctx.admin, &true, &0);

    assert_qx_err(
        ctx.client.try_batch_create(&creates),
        QuickexError::ContractPaused,
    );
    assert_qx_err(
        ctx.client.try_batch_release(&releases),
        QuickexError::ContractPaused,
    );
    assert_qx_err(
        ctx.client.try_batch_refund(&ctx.alice, &refunds),
        QuickexError::ContractPaused,
    );

    assert_eq!(
        balance(&ctx, &ctx.client.address),
        AMOUNT,
        "no funds moved while paused"
    );
    assert_eq!(balance(&ctx, &ctx.alice), 0);
}

/// Emergency mode blocks `batch_create` (new money in) but keeps the
/// fund-recovery paths `batch_release` and `batch_refund` open — exactly the
/// split the single-item `Deposit` / `Withdraw` / `Refund` entry points have.
#[test]
fn emergency_mode_blocks_create_but_allows_release_and_refund() {
    let ctx = setup();
    ctx.mint(&ctx.alice, AMOUNT * 2);

    // Fund two escrows before the freeze: one to release, one to let expire.
    let releasable = fund(&ctx, &ctx.alice, 1, 0, AMOUNT, TIMEOUT)
        .get(0)
        .unwrap();
    fund(&ctx, &ctx.alice, 1, 1, AMOUNT, TIMEOUT);
    assert_eq!(balance(&ctx, &ctx.client.address), AMOUNT * 2);

    ctx.client.activate_emergency_mode(&ctx.admin);
    assert!(ctx.client.is_emergency_mode());

    // Allowlist introspection matches the single-item flows.
    assert!(!ctx
        .client
        .is_entry_allowed_in_emergency(&EntryPoint::BatchCreate));
    assert!(ctx
        .client
        .is_entry_allowed_in_emergency(&EntryPoint::BatchRelease));
    assert!(ctx
        .client
        .is_entry_allowed_in_emergency(&EntryPoint::BatchRefund));

    // Create is blocked.
    let mut blocked: Vec<BatchCreateItem> = Vec::new(&ctx.env);
    blocked.push_back(create_item(&ctx, 2, &ctx.alice, AMOUNT, 0));
    assert_qx_err(
        ctx.client.try_batch_create(&blocked),
        QuickexError::ContractPaused,
    );

    // Release still works and still moves the money.
    let mut releases: Vec<BatchReleaseItem> = Vec::new(&ctx.env);
    releases.push_back(release_item(&ctx, 0, &ctx.alice, AMOUNT));
    assert_success(&ctx.client.batch_release(&releases).get(0).unwrap(), 0);
    assert_eq!(balance(&ctx, &ctx.alice), AMOUNT);
    assert_escrow_spent(&ctx.client, &releasable);

    // Refund still works and still returns money to the owner.
    ctx.advance_time(TIMEOUT);
    let mut refunds: Vec<BatchRefundItem> = Vec::new(&ctx.env);
    refunds.push_back(refund_item(&ctx.commitment(&ctx.alice, AMOUNT, &[1])));
    assert_success(
        &ctx.client
            .batch_refund(&ctx.alice, &refunds)
            .get(0)
            .unwrap(),
        0,
    );
    assert_eq!(balance(&ctx, &ctx.client.address), 0);
    assert_eq!(balance(&ctx, &ctx.alice), AMOUNT * 2);
}
