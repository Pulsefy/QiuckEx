//! Hot-path budget benchmarks for the QuickEx contract.
//!
//! Uses Soroban's built-in `env.budget()` metering to measure CPU instruction
//! count and memory bytes for each hot-path function.
//!
//! ## Running
//!
//! ```sh
//! cargo test bench_ -- --nocapture
//! ```
//!
//! ## Interpretation
//! - Numbers are native-Rust estimates (not WASM). They correctly show
//!   *relative* improvement between before/after optimisation, even if the
//!   absolute values differ from on-chain costs.
//! - Budget is reset immediately before the hot-path call so setup overhead
//!   (token minting, escrow seeding, etc.) is excluded from measurements.

extern crate std;

use crate::{
    storage::{put_escrow, DataKey, PRIVACY_ENABLED_KEY}, EscrowEntry, EscrowStatus,
    QuickexContract, QuickexContractClient,
};
use soroban_sdk::{
    testutils::Address as _, token, xdr::ToXdr, Address, Bytes, BytesN, Env, Symbol,
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn setup<'a>() -> (Env, QuickexContractClient<'a>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    (env, client)
}

fn create_test_token(env: &Env) -> Address {
    env.register_stellar_asset_contract_v2(Address::generate(env))
        .address()
}

/// Seed an escrow directly into storage (bypasses token transfer — we only
/// want to measure the withdrawal hot path, not the token mint).
fn seed_escrow(
    env: &Env,
    contract_id: &Address,
    token: &Address,
    owner: &Address,
    amount: i128,
    commitment: BytesN<32>,
) {
    let entry = EscrowEntry {
        token: token.clone(),
        amount,
        owner: owner.clone(),
        status: EscrowStatus::Pending,
        created_at: env.ledger().timestamp(),
        expires_at: 0,
        arbiter: None,
    };
    env.as_contract(contract_id, || {
        let key: Bytes = commitment.into();
        put_escrow(env, &key, &entry);
    });
}

/// Compute the same commitment hash used by the contract:
/// SHA256(XDR(owner) || BE(amount) || salt)
fn make_commitment(env: &Env, owner: &Address, amount: i128, salt: &Bytes) -> BytesN<32> {
    let mut data = Bytes::new(env);
    data.append(&owner.clone().to_xdr(env));
    data.append(&Bytes::from_slice(env, &amount.to_be_bytes()));
    data.append(salt);
    env.crypto().sha256(&data).into()
}

fn print_budget(env: &Env, label: &str) {
    let cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let mem = env.cost_estimate().budget().memory_bytes_cost();
    std::println!("[bench] {label:<35}  cpu={cpu:<12}  mem={mem}");
}

fn legacy_privacy_storage_key(env: &Env, owner: &Address) -> (Symbol, Address) {
    (Symbol::new(env, PRIVACY_ENABLED_KEY), owner.clone())
}

// ---------------------------------------------------------------------------
// Hot-path benchmarks
// ---------------------------------------------------------------------------

/// Benchmark: create_amount_commitment
/// Deepest hot path — called inside every deposit and withdraw.
#[test]
fn bench_create_amount_commitment() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"bench_salt_commitment");

    // --- Reset budget immediately before the hot path ---
    env.cost_estimate().budget().reset_default();
    let _ = client.create_amount_commitment(&owner, &1_000_000i128, &salt);
    print_budget(&env, "create_amount_commitment");
}

/// Benchmark: deposit
/// Called every time funds are escrowed (highest volume).
#[test]
fn bench_deposit() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"bench_salt_deposit");
    let amount: i128 = 1_000_000;

    // Setup: mint tokens so the transfer succeeds — excluded from measurement
    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&owner, &amount);

    // --- Reset budget immediately before the hot path ---
    env.cost_estimate().budget().reset_default();
    let _ = client.deposit(&token, &amount, &owner, &salt, &0u64, &None);
    print_budget(&env, "deposit");
}

/// Benchmark: deposit_with_commitment
/// Called every time funds are escrowed via pre-generated commitment.
#[test]
fn bench_deposit_with_commitment() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let from = Address::generate(&env);
    let amount: i128 = 1_000_000;
    let commitment = BytesN::from_array(&env, &[0xABu8; 32]);

    // Setup: mint tokens — excluded from measurement
    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&from, &amount);

    // --- Reset budget immediately before the hot path ---
    env.cost_estimate().budget().reset_default();
    client.deposit_with_commitment(&from, &token, &amount, &commitment, &0u64, &None);
    print_budget(&env, "deposit_with_commitment");
}

/// Benchmark: withdraw
/// Called every time funds are claimed (equally high volume).
#[test]
fn bench_withdraw() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"bench_salt_withdraw");
    let amount: i128 = 1_000_000;

    // Setup: seed escrow + mint tokens to contract — excluded from measurement
    let commitment = make_commitment(&env, &owner, amount, &salt);
    seed_escrow(
        &env,
        &client.address,
        &token,
        &owner,
        amount,
        commitment.clone(),
    );
    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&client.address, &amount);

    // --- Reset budget immediately before the hot path ---
    env.cost_estimate().budget().reset_default();
    client.withdraw(&token, &amount, &commitment, &owner, &salt);
    print_budget(&env, "withdraw");
}

/// Benchmark: set_privacy
/// Medium frequency — per user preference change.
#[test]
fn bench_set_privacy() {
    let (env, client) = setup();
    let owner = Address::generate(&env);

    // --- Reset budget immediately before the hot path ---
    env.cost_estimate().budget().reset_default();
    client.set_privacy(&owner, &true);
    print_budget(&env, "set_privacy");
}

/// Benchmark: get_privacy
/// Medium frequency — read-only companion to set_privacy.
#[test]
fn bench_get_privacy() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    // Set it first so the storage path is exercised (not just the default)
    client.set_privacy(&owner, &true);

    // --- Reset budget immediately before the hot path ---
    env.cost_estimate().budget().reset_default();
    let _ = client.get_privacy(&owner);
    print_budget(&env, "get_privacy");
}

/// Benchmark: legacy privacy-key read
/// Measures the pre-migration `(Symbol, Address)` storage path directly.
#[test]
fn bench_legacy_privacy_key_read() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let key = legacy_privacy_storage_key(&env, &owner);
    env.storage().persistent().set(&key, &true);

    env.cost_estimate().budget().reset_default();
    let _: bool = env.storage().persistent().get(&key).unwrap_or(false);
    print_budget(&env, "legacy_privacy_key_read");
}

/// Benchmark: typed privacy-key read
/// Measures the `DataKey::PrivacyEnabled` storage path used by privacy checks.
#[test]
fn bench_typed_privacy_key_read() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let key = DataKey::PrivacyEnabled(owner);
    env.storage().persistent().set(&key, &true);

    env.cost_estimate().budget().reset_default();
    let _: bool = env.storage().persistent().get(&key).unwrap_or(false);
    print_budget(&env, "typed_privacy_key_read");
}

/// Benchmark: legacy privacy-key write
/// Measures the pre-migration `(Symbol, Address)` storage write path directly.
#[test]
fn bench_legacy_privacy_key_write() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let key = legacy_privacy_storage_key(&env, &owner);

    env.cost_estimate().budget().reset_default();
    env.storage().persistent().set(&key, &true);
    print_budget(&env, "legacy_privacy_key_write");
}

/// Benchmark: typed privacy-key write
/// Measures the `DataKey::PrivacyEnabled` storage write path used by privacy toggles.
#[test]
fn bench_typed_privacy_key_write() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let key = DataKey::PrivacyEnabled(owner);

    env.cost_estimate().budget().reset_default();
    env.storage().persistent().set(&key, &true);
    print_budget(&env, "typed_privacy_key_write");
}

/// Benchmark: verify_proof_view
/// Medium frequency — called before withdrawals to pre-check.
#[test]
fn bench_verify_proof_view() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"bench_salt_proof");
    let amount: i128 = 1_000_000;

    // Setup: seed a valid pending escrow — excluded from measurement
    let commitment = make_commitment(&env, &owner, amount, &salt);
    seed_escrow(&env, &client.address, &token, &owner, amount, commitment);

    // --- Reset budget immediately before the hot path ---
    env.cost_estimate().budget().reset_default();
    let _ = client.verify_proof_view(&amount, &salt, &owner);
    print_budget(&env, "verify_proof_view");
}
