//! SC-W6-06 — regression tests
//!
//! These tests verify that semantic behaviour is UNCHANGED after the
//! storage-compaction refactor.  Every test mirrors what the original
//! (pre-compaction) contract was supposed to do; the assertions act as
//! an "XDR golden file" for observable behaviour.

#![cfg(test)]

use soroban_sdk::{
    symbol_short, testutils::Address as _, Address, Env, String, Symbol,
};

use quickex_contract::{flags, DataKey, PaymentLink, QuickExContract, QuickExContractClient, UserRecord};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn setup() -> (Env, QuickExContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, QuickExContract);
    let client = QuickExContractClient::new(&env, &contract_id);
    (env, client)
}

fn alice(env: &Env) -> Address {
    Address::generate(env)
}

fn usdc(env: &Env) -> Symbol {
    Symbol::new(env, "USDC")
}

fn xlm() -> Symbol {
    symbol_short!("XLM")
}

fn memo(env: &Env, s: &str) -> String {
    String::from_str(env, s)
}

fn uname(env: &Env, s: &str) -> Symbol {
    Symbol::new(env, s)
}

// ── Registration ──────────────────────────────────────────────────────────────

#[test]
fn test_register_stores_user_record() {
    let (env, client) = setup();
    let owner = alice(&env);
    let username = uname(&env, "alice");

    client.register(&username, &owner);

    let rec = client.get_user(&username).expect("record must exist");
    assert_eq!(rec.owner, owner, "owner address preserved");
    assert_eq!(rec.link_count, 0, "fresh account has zero links");
    assert_eq!(rec.total_received, 0, "fresh account has zero receipts");
    // registered_at is set to ledger timestamp; just verify it is non-zero
    // in a mock env the default timestamp is 0 — check it is stored.
    assert_eq!(rec.registered_at, env.ledger().timestamp());
}

#[test]
#[should_panic(expected = "username already taken")]
fn test_register_duplicate_panics() {
    let (env, client) = setup();
    let owner = alice(&env);
    let username = uname(&env, "alice");
    client.register(&username, &owner);
    client.register(&username, &owner); // must panic
}

// ── Link creation ─────────────────────────────────────────────────────────────

#[test]
fn test_create_link_returns_sequential_ids() {
    let (env, client) = setup();
    let owner = alice(&env);
    let username = uname(&env, "bob");
    client.register(&username, &owner);

    let id0 = client.create_link(&username, &1_000_000i128, &usdc(&env), &memo(&env, "gig"), &false);
    let id1 = client.create_link(&username, &2_000_000i128, &usdc(&env), &memo(&env, "tip"), &false);

    assert_eq!(id0, 0u32);
    assert_eq!(id1, 1u32);
}

#[test]
fn test_create_link_increments_link_count() {
    let (env, client) = setup();
    let owner = alice(&env);
    let username = uname(&env, "carol");
    client.register(&username, &owner);

    client.create_link(&username, &500_000i128, &xlm(), &memo(&env, "test"), &false);
    client.create_link(&username, &500_000i128, &xlm(), &memo(&env, "test2"), &false);

    let rec = client.get_user(&username).unwrap();
    assert_eq!(rec.link_count, 2);
}

#[test]
fn test_create_link_privacy_flag_stored() {
    let (env, client) = setup();
    let owner = alice(&env);
    let username = uname(&env, "dave");
    client.register(&username, &owner);

    let id = client.create_link(&username, &0i128, &usdc(&env), &memo(&env, ""), &true);

    let link = client.get_link(&username, &id).unwrap();
    assert!(link.privacy_enabled(), "privacy flag must survive round-trip");
    assert!(!link.is_revoked(), "fresh link must not be revoked");
}

#[test]
fn test_create_link_no_privacy_flag() {
    let (env, client) = setup();
    let owner = alice(&env);
    let username = uname(&env, "eve");
    client.register(&username, &owner);

    let id = client.create_link(&username, &1_000i128, &usdc(&env), &memo(&env, "plain"), &false);

    let link = client.get_link(&username, &id).unwrap();
    assert!(!link.privacy_enabled());
    assert_eq!(link.flags & flags::PRIVACY_ENABLED, 0);
}

#[test]
fn test_link_asset_and_amount_preserved() {
    let (env, client) = setup();
    let owner = alice(&env);
    let username = uname(&env, "frank");
    client.register(&username, &owner);

    let id = client.create_link(
        &username,
        &9_999_999i128,
        &usdc(&env),
        &memo(&env, "invoice #42"),
        &false,
    );

    let link = client.get_link(&username, &id).unwrap();
    assert_eq!(link.amount, 9_999_999i128);
    assert_eq!(link.memo, memo(&env, "invoice #42"));
}

#[test]
fn test_get_link_missing_returns_none() {
    let (env, client) = setup();
    let username = uname(&env, "ghost");
    assert!(client.get_link(&username, &0u32).is_none());
}

// ── Revocation ────────────────────────────────────────────────────────────────

#[test]
fn test_revoke_sets_revoked_flag() {
    let (env, client) = setup();
    let owner = alice(&env);
    let username = uname(&env, "grace");
    client.register(&username, &owner);

    let id = client.create_link(&username, &100i128, &xlm(), &memo(&env, ""), &false);
    client.revoke_link(&username, &id);

    let link = client.get_link(&username, &id).unwrap();
    assert!(link.is_revoked(), "REVOKED flag must be set after revoke_link");
}

#[test]
fn test_revoke_preserves_other_flags() {
    let (env, client) = setup();
    let owner = alice(&env);
    let username = uname(&env, "harry");
    client.register(&username, &owner);

    // Create with privacy ON, then revoke — both flags must be set.
    let id = client.create_link(&username, &100i128, &xlm(), &memo(&env, ""), &true);
    client.revoke_link(&username, &id);

    let link = client.get_link(&username, &id).unwrap();
    assert!(link.privacy_enabled(), "PRIVACY flag must survive revocation");
    assert!(link.is_revoked(), "REVOKED flag must be set");
}

// ── Payment recording ─────────────────────────────────────────────────────────

#[test]
fn test_record_payment_accumulates() {
    let (env, client) = setup();
    let owner = alice(&env);
    let username = uname(&env, "ivan");
    client.register(&username, &owner);

    client.record_payment(&username, &1_000_000i128);
    client.record_payment(&username, &2_500_000i128);

    let rec = client.get_user(&username).unwrap();
    assert_eq!(rec.total_received, 3_500_000i128);
}

// ── Global counter ────────────────────────────────────────────────────────────

#[test]
fn test_total_links_counter() {
    let (env, client) = setup();
    let owner = alice(&env);

    assert_eq!(client.total_links(), 0);

    let u1 = uname(&env, "judy");
    let u2 = uname(&env, "karl");
    client.register(&u1, &owner);
    client.register(&u2, &owner);

    client.create_link(&u1, &0i128, &xlm(), &memo(&env, "a"), &false);
    client.create_link(&u1, &0i128, &xlm(), &memo(&env, "b"), &false);
    client.create_link(&u2, &0i128, &xlm(), &memo(&env, "c"), &false);

    assert_eq!(client.total_links(), 3);
}

// ── Storage footprint assertions ──────────────────────────────────────────────
//
// These tests don't assert exact byte counts (which would be fragile across
// SDK versions) but verify structural properties that guarantee compaction:
//   1. The UserRecord stored under a key does NOT contain a duplicate username.
//   2. A PaymentLink stored under a key does NOT contain a username field.
//   3. link_count is u32 (verified by type; compile-time guarantee).

#[test]
fn test_user_record_has_no_username_field() {
    // Compile-time: UserRecord has no `username` field.
    // If someone accidentally re-adds it, this won't compile.
    let _r: UserRecord = UserRecord {
        owner: Address::generate(&Env::default()),
        link_count: 0u32,   // u32, not u64
        total_received: 0i128,
        registered_at: 0u64,
    };
    // No `username` field required — proves compaction.
}

#[test]
fn test_payment_link_has_no_username_field() {
    let env = Env::default();
    let _l: PaymentLink = PaymentLink {
        amount: 0i128,
        asset: symbol_short!("XLM"),
        memo: String::from_str(&env, ""),
        flags: 0u32,        // bool packed into bitfield
        created_at: 0u64,
        creator: Address::generate(&env),
    };
    // No `username` or `privacy: bool` fields — proves compaction.
}