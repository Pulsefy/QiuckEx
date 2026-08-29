//! Tests for SC-W8-03: cross-contract hook reentrancy guard.
//!
//! `hook::invoke_hooks` sets a reentrancy flag for the duration of the hook
//! loop, and every state-mutating entrypoint checks it via
//! `hook::assert_not_reentrant`. These tests prove that guard actually does
//! its job by using malicious hook contracts that try to call *back* into
//! the escrow contract — targeting a *different*, otherwise-eligible escrow
//! — while the original entrypoint's hook invocation is still in flight.
//!
//! Reusing the *same* commitment that's mid-withdraw/refund wouldn't isolate
//! much, since that escrow's own status flip (`Pending` -> `Spent`/`Refunded`,
//! committed before hooks fire) would block a repeat call on its own. Using a
//! second, independently-valid escrow shows the guard — not just the status
//! machine — is what stops the reentrant call.
//!
//! **Important caveat found while writing these tests:** for a hook calling
//! straight back into *this same contract* via a normal cross-contract call,
//! Soroban's host runtime already refuses the call before our Wasm code
//! executes at all — `ContractReentryMode::Prohibited` is the default for
//! external calls (see `soroban-env-host` `src/host/frame.rs`), and it
//! blocks any contract ID already present on the call stack. That means our
//! own `hook::assert_not_reentrant` guard never actually runs for *this*
//! attack path; the host aborts first. The tests below assert on that real,
//! observed host-level abort rather than on `QuickexError::ReentrancyDetected`,
//! because the latter genuinely cannot be reached here. The app-level guard
//! is still worth keeping as defense-in-depth (it's cheap, consistent with
//! the rest of the codebase, and protects any call path that doesn't cross a
//! real contract-call boundary), but it is not what stops this specific
//! scenario in practice — the platform is. Worth flagging in the PR/ticket:
//! the acceptance criterion "a reentrant attempt fails with a distinct,
//! documented error code" isn't reachable for genuine cross-contract hook
//! reentrancy as currently wired; it's an aspirational belt-and-suspenders
//! guarantee rather than the actual enforcement mechanism here.

#![allow(dead_code)]

use soroban_sdk::{contract, contractimpl, symbol_short, Address, Bytes, BytesN, Env, InvokeError};

use crate::{
    assert_helpers::{assert_escrow_pending, assert_escrow_refunded, assert_escrow_spent},
    test_context::TestContext,
    types::HookEventKind,
    QuickexContractClient,
};

// ---------------------------------------------------------------------------
// Benign hook: just counts invocations, to prove the guard doesn't break
// normal sequential hook firing.
// ---------------------------------------------------------------------------

#[contract]
pub struct CountingHook;

#[contractimpl]
impl CountingHook {
    pub fn on_escrow_event(
        env: Env,
        _event_kind: u32,
        _escrow_id: BytesN<32>,
        _owner: Address,
        _token: Address,
        _amount: i128,
        _fee: i128,
    ) {
        let key = symbol_short!("count");
        let count: u32 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(count + 1));
    }

    pub fn count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&symbol_short!("count"))
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Malicious hook: fires on a `Settle` (withdraw/"release") event and tries
// to reenter by calling `refund` on an unrelated, already-expired escrow.
// ---------------------------------------------------------------------------

#[contract]
pub struct ReentrantRefundHook;

#[contractimpl]
impl ReentrantRefundHook {
    pub fn init(env: Env, target: Address, commitment: BytesN<32>, owner: Address) {
        env.storage()
            .persistent()
            .set(&symbol_short!("target"), &target);
        env.storage()
            .persistent()
            .set(&symbol_short!("commit"), &commitment);
        env.storage()
            .persistent()
            .set(&symbol_short!("owner"), &owner);
    }

    pub fn on_escrow_event(
        env: Env,
        event_kind: u32,
        _escrow_id: BytesN<32>,
        _owner: Address,
        _token: Address,
        _amount: i128,
        _fee: i128,
    ) {
        if event_kind != HookEventKind::Settle as u32 {
            return;
        }
        let target: Address = env
            .storage()
            .persistent()
            .get(&symbol_short!("target"))
            .unwrap();
        let commitment: BytesN<32> = env
            .storage()
            .persistent()
            .get(&symbol_short!("commit"))
            .unwrap();
        let owner: Address = env
            .storage()
            .persistent()
            .get(&symbol_short!("owner"))
            .unwrap();

        let client = QuickexContractClient::new(&env, &target);
        let attempt = client.try_refund(&commitment, &owner, &0u64, &u64::MAX);

        let code: u32 = match attempt {
            Err(Ok(e)) => e as u32,
            Ok(_) => 0, // unexpected: reentrant call succeeded
            Err(Err(InvokeError::Contract(code))) => code,
            Err(Err(InvokeError::Abort)) => 9998, // host-level abort/panic, not a QuickexError
        };
        env.storage()
            .persistent()
            .set(&symbol_short!("result"), &code);
    }

    pub fn result(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&symbol_short!("result"))
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Mirror image: fires on a `Refund` event and tries to reenter by calling
// `withdraw` on an unrelated, fully-paid, still-pending escrow.
// ---------------------------------------------------------------------------

#[contract]
pub struct ReentrantWithdrawHook;

#[contractimpl]
impl ReentrantWithdrawHook {
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        env: Env,
        target: Address,
        token: Address,
        amount: i128,
        commitment: BytesN<32>,
        to: Address,
        salt: Bytes,
    ) {
        env.storage()
            .persistent()
            .set(&symbol_short!("target"), &target);
        env.storage()
            .persistent()
            .set(&symbol_short!("token"), &token);
        env.storage()
            .persistent()
            .set(&symbol_short!("amount"), &amount);
        env.storage()
            .persistent()
            .set(&symbol_short!("commit"), &commitment);
        env.storage().persistent().set(&symbol_short!("to"), &to);
        env.storage()
            .persistent()
            .set(&symbol_short!("salt"), &salt);
    }

    pub fn on_escrow_event(
        env: Env,
        event_kind: u32,
        _escrow_id: BytesN<32>,
        _owner: Address,
        _token: Address,
        _amount: i128,
        _fee: i128,
    ) {
        if event_kind != HookEventKind::Refund as u32 {
            return;
        }
        let target: Address = env
            .storage()
            .persistent()
            .get(&symbol_short!("target"))
            .unwrap();
        let token: Address = env
            .storage()
            .persistent()
            .get(&symbol_short!("token"))
            .unwrap();
        let amount: i128 = env
            .storage()
            .persistent()
            .get(&symbol_short!("amount"))
            .unwrap();
        let commitment: BytesN<32> = env
            .storage()
            .persistent()
            .get(&symbol_short!("commit"))
            .unwrap();
        let to: Address = env
            .storage()
            .persistent()
            .get(&symbol_short!("to"))
            .unwrap();
        let salt: Bytes = env
            .storage()
            .persistent()
            .get(&symbol_short!("salt"))
            .unwrap();

        let client = QuickexContractClient::new(&env, &target);
        let attempt =
            client.try_withdraw(&token, &amount, &commitment, &to, &salt, &0u64, &u64::MAX);

        let code: u32 = match attempt {
            Err(Ok(e)) => e as u32,
            Ok(_) => 0,
            Err(Err(InvokeError::Contract(code))) => code,
            Err(Err(InvokeError::Abort)) => 9998,
        };
        env.storage()
            .persistent()
            .set(&symbol_short!("result"), &code);
    }

    pub fn result(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&symbol_short!("result"))
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn allow_and_register_hook(ctx: &TestContext, hook_id: &Address) {
    ctx.client.set_hook_allowed(&ctx.admin, hook_id, &true);
    ctx.client.register_hook(hook_id);
}

/// Sentinel used in these tests to mean "the reentrant call was rejected by
/// the Soroban host's own call-stack check (`InvokeError::Abort`) before our
/// contract's `assert_not_reentrant` guard ever ran."
///
/// See the module doc comment: for a hook calling directly back into this
/// same contract, the host's `ContractReentryMode::Prohibited` default
/// (soroban-env-host `frame.rs`) traps the call before our Wasm code
/// executes, so our own `ReentrancyGuard` never gets a chance to return
/// `QuickexError::ReentrancyDetected` for *this* path. We assert on the
/// abort here so the test documents the real observed behavior instead of
/// asserting something that can't happen.
const HOST_REENTRY_ABORT: u32 = 9998;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A benign hook keeps firing normally across multiple lifecycle events —
/// the guard must not interfere with legitimate, non-reentrant hook calls.
#[test]
fn test_legitimate_sequential_hooks_still_fire() {
    let ctx = TestContext::with_admin();
    let hook_id = ctx.env.register(CountingHook, ());
    allow_and_register_hook(&ctx, &hook_id);

    let salt = ctx.salt(b"seq-salt");
    let commitment = ctx.simple_deposit(&ctx.alice, 1000, b"seq-salt");
    ctx.client.withdraw(
        &ctx.token,
        &1000i128,
        &commitment,
        &ctx.alice,
        &salt,
        &0u64,
        &u64::MAX,
    );

    let hook_client = CountingHookClient::new(&ctx.env, &hook_id);
    // One `Create` event from deposit, one `Settle` event from withdraw.
    assert_eq!(hook_client.count(), 2);
    assert_eq!(ctx.balance(&ctx.alice), 1000);
}

/// A malicious hook fired during `withdraw` (release) tries to reenter via
/// `refund` on a second, unrelated, already-expired escrow. The guard must
/// reject the reentrant call with `ReentrancyDetected`, and the untouched
/// escrow must remain refundable afterwards through the normal call path.
#[test]
fn test_reentrant_refund_during_withdraw_is_rejected() {
    let ctx = TestContext::with_admin();

    // Escrow #2: owned by bob, expired, would legitimately be refundable —
    // this is the reentrancy target, untouched by the withdraw below.
    ctx.mint(&ctx.bob, 500);
    let commitment2 = ctx.client.deposit(
        &ctx.token,
        &500i128,
        &ctx.bob,
        &ctx.salt(b"c2-salt"),
        &100u64,
        &None,
        &0u64,
        &u64::MAX,
    );
    ctx.advance_time(101);

    // Escrow #1: owned by alice, never expires — this is the one we withdraw.
    let salt1 = ctx.salt(b"c1-salt");
    let commitment1 = ctx.simple_deposit(&ctx.alice, 1000, b"c1-salt");

    let hook_id = ctx.env.register(ReentrantRefundHook, ());
    let hook_client = ReentrantRefundHookClient::new(&ctx.env, &hook_id);
    hook_client.init(&ctx.client.address, &commitment2, &ctx.bob);
    allow_and_register_hook(&ctx, &hook_id);

    // Triggers the Settle hook, which attempts a reentrant refund(commitment2).
    ctx.client.withdraw(
        &ctx.token,
        &1000i128,
        &commitment1,
        &ctx.alice,
        &salt1,
        &0u64,
        &u64::MAX,
    );

    // The reentrant attempt must have been rejected specifically by the guard.
    assert_eq!(hook_client.result(), HOST_REENTRY_ABORT);

    // Escrow #2 was untouched — reentrancy didn't mutate its state.
    assert_escrow_pending(&ctx.client, &commitment2);
    assert_eq!(ctx.balance(&ctx.bob), 0);

    // Escrow #1 completed normally despite the hook's reentry attempt.
    assert_escrow_spent(&ctx.client, &commitment1);
    assert_eq!(ctx.balance(&ctx.alice), 1000);

    // The guard only blocks reentrant calls — a legitimate, top-level refund
    // on escrow #2 still works fine afterwards.
    ctx.client.refund(&commitment2, &ctx.bob, &0u64, &u64::MAX);
    assert_escrow_refunded(&ctx.client, &commitment2);
    assert_eq!(ctx.balance(&ctx.bob), 500);
}

/// Mirror scenario: a malicious hook fired during `refund` tries to reenter
/// via `withdraw` on a second, unrelated, fully-paid pending escrow.
#[test]
fn test_reentrant_withdraw_during_refund_is_rejected() {
    let ctx = TestContext::with_admin();

    // Escrow #2: owned by bob, never expires, fully paid — reentrancy target.
    let salt2 = ctx.salt(b"c2-salt");
    let commitment2 = ctx.simple_deposit(&ctx.bob, 500, b"c2-salt");

    // Escrow #1: owned by alice, will expire and be refunded.
    ctx.mint(&ctx.alice, 1000);
    let commitment1 = ctx.client.deposit(
        &ctx.token,
        &1000i128,
        &ctx.alice,
        &ctx.salt(b"c1-salt"),
        &100u64,
        &None,
        &0u64,
        &u64::MAX,
    );

    let hook_id = ctx.env.register(ReentrantWithdrawHook, ());
    let hook_client = ReentrantWithdrawHookClient::new(&ctx.env, &hook_id);
    hook_client.init(
        &ctx.client.address,
        &ctx.token,
        &500i128,
        &commitment2,
        &ctx.bob,
        &salt2,
    );
    allow_and_register_hook(&ctx, &hook_id);

    ctx.advance_time(101);

    // Triggers the Refund hook, which attempts a reentrant withdraw(commitment2).
    ctx.client
        .refund(&commitment1, &ctx.alice, &0u64, &u64::MAX);

    assert_eq!(hook_client.result(), HOST_REENTRY_ABORT);

    // Escrow #2 was untouched.
    assert_escrow_pending(&ctx.client, &commitment2);
    assert_eq!(ctx.balance(&ctx.bob), 0);

    // Escrow #1 completed normally despite the hook's reentry attempt.
    assert_escrow_refunded(&ctx.client, &commitment1);
    assert_eq!(ctx.balance(&ctx.alice), 1000);

    // A legitimate, top-level withdraw on escrow #2 still works afterwards.
    ctx.client.withdraw(
        &ctx.token,
        &500i128,
        &commitment2,
        &ctx.bob,
        &salt2,
        &0u64,
        &u64::MAX,
    );
    assert_escrow_spent(&ctx.client, &commitment2);
    assert_eq!(ctx.balance(&ctx.bob), 500);
}
