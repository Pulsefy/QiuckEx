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
    storage::{
        compact_escrow_storage_footprint_bytes, legacy_escrow_storage_footprint_bytes, put_escrow,
        DataKey, PRIVACY_ENABLED_KEY,
    },
    EscrowEntry, EscrowStatus, QuickexContract, QuickexContractClient,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Symbol, Vec,
};
use std::{format, string::String, vec::Vec as StdVec};

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
        amount_due: amount,
        amount_paid: amount,
        owner: owner.clone(),
        status: EscrowStatus::Pending,
        created_at: env.ledger().timestamp(),
        expires_at: 0,
        arbiter: None,
        #[allow(clippy::needless_borrow)]
        arbiters: Vec::new(&env),
        arbiter_threshold: 0,
    };
    env.as_contract(contract_id, || {
        let key: Bytes = commitment.into();
        put_escrow(env, &key, &entry);
    });
}

/// Compute the same commitment hash used by the contract:
/// KECCAK256(XDR(owner) || BE(amount) || salt)
fn make_commitment(env: &Env, owner: &Address, amount: i128, salt: &Bytes) -> BytesN<32> {
    let mut data = Bytes::new(env);
    data.append(&owner.clone().to_xdr(env));
    data.append(&Bytes::from_slice(env, &amount.to_be_bytes()));
    data.append(salt);
    env.crypto().keccak256(&data).into()
}

fn make_commitment_payload(env: &Env, owner: &Address, amount: i128, salt: &Bytes) -> Bytes {
    let mut data = Bytes::new(env);
    data.append(&owner.clone().to_xdr(env));
    data.append(&Bytes::from_slice(env, &amount.to_be_bytes()));
    data.append(salt);
    data
}

fn print_budget(env: &Env, label: &str) {
    let cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let mem = env.cost_estimate().budget().memory_bytes_cost();
    std::println!("[bench] {label:<35}  cpu={cpu:<12}  mem={mem}");
}

#[derive(Clone, Copy)]
struct CoreBenchResult {
    operation: &'static str,
    cpu_instructions: u64,
    memory_bytes: u64,
    storage_fee_bytes: u64,
    max_cpu_instructions: u64,
    max_memory_bytes: u64,
    max_storage_fee_bytes: u64,
}

impl CoreBenchResult {
    fn assert_within_threshold(self) {
        assert!(
            self.cpu_instructions <= self.max_cpu_instructions,
            "{} CPU instruction regression: actual={} max={}",
            self.operation,
            self.cpu_instructions,
            self.max_cpu_instructions
        );
        assert!(
            self.memory_bytes <= self.max_memory_bytes,
            "{} memory regression: actual={} max={}",
            self.operation,
            self.memory_bytes,
            self.max_memory_bytes
        );
        assert!(
            self.storage_fee_bytes <= self.max_storage_fee_bytes,
            "{} storage fee regression: actual={} max={}",
            self.operation,
            self.storage_fee_bytes,
            self.max_storage_fee_bytes
        );
    }
}

fn storage_bytes_for_pair<K: ToXdr + Clone, V: ToXdr + Clone>(env: &Env, key: &K, value: &V) -> u64 {
    key.clone().to_xdr(env).len() as u64 + value.clone().to_xdr(env).len() as u64
}

fn escrow_storage_fee_bytes(env: &Env, commitment: &BytesN<32>, entry: &EscrowEntry) -> u64 {
    let commitment_bytes: Bytes = commitment.clone().into();
    storage_bytes_for_pair(env, &DataKey::Escrow(commitment_bytes), entry)
}

fn escrow_id_storage_fee_bytes(env: &Env, escrow_id: &BytesN<32>, commitment: &BytesN<32>) -> u64 {
    storage_bytes_for_pair(env, &DataKey::EscrowIdMap(escrow_id.clone()), commitment)
}

fn measured_budget(env: &Env) -> (u64, u64) {
    (
        env.cost_estimate().budget().cpu_instruction_cost(),
        env.cost_estimate().budget().memory_bytes_cost(),
    )
}

fn bench_core_op<F>(
    env: &Env,
    operation: &'static str,
    storage_fee_bytes: u64,
    max_cpu_instructions: u64,
    max_memory_bytes: u64,
    max_storage_fee_bytes: u64,
    run: F,
) -> CoreBenchResult
where
    F: FnOnce(),
{
    env.cost_estimate().budget().reset_default();
    run();
    let (cpu_instructions, memory_bytes) = measured_budget(env);
    let result = CoreBenchResult {
        operation,
        cpu_instructions,
        memory_bytes,
        storage_fee_bytes,
        max_cpu_instructions,
        max_memory_bytes,
        max_storage_fee_bytes,
    };
    std::println!(
        "[bench-core] {:<8} cpu={} mem={} storage_fee_bytes={}",
        operation,
        cpu_instructions,
        memory_bytes,
        storage_fee_bytes
    );
    result
}

fn write_core_bench_artifacts(results: &[CoreBenchResult]) {
    let artifact_dir = match std::env::var("QUICKEX_BENCH_ARTIFACT_DIR") {
        Ok(path) => path,
        Err(_) => return,
    };

    std::fs::create_dir_all(&artifact_dir).expect("create benchmark artifact directory");

    let mut json = String::from("{\n  \"suite\": \"quickex-core-flow-costs\",\n  \"results\": [\n");
    for (idx, result) in results.iter().enumerate() {
        let comma = if idx + 1 == results.len() { "" } else { "," };
        json.push_str(&format!(
            "    {{ \"operation\": \"{}\", \"cpu_instructions\": {}, \"memory_bytes\": {}, \"storage_fee_bytes\": {}, \"thresholds\": {{ \"cpu_instructions\": {}, \"memory_bytes\": {}, \"storage_fee_bytes\": {} }} }}{}\n",
            result.operation,
            result.cpu_instructions,
            result.memory_bytes,
            result.storage_fee_bytes,
            result.max_cpu_instructions,
            result.max_memory_bytes,
            result.max_storage_fee_bytes,
            comma
        ));
    }
    json.push_str("  ]\n}\n");

    let mut markdown = String::from(
        "# QuickEx Core Flow Cost Benchmarks\n\n| Operation | CPU instructions | Memory bytes | Storage fee bytes | CPU max | Memory max | Storage max |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n",
    );
    for result in results {
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            result.operation,
            result.cpu_instructions,
            result.memory_bytes,
            result.storage_fee_bytes,
            result.max_cpu_instructions,
            result.max_memory_bytes,
            result.max_storage_fee_bytes
        ));
    }

    std::fs::write(
        format!("{artifact_dir}/quickex-core-benchmarks.json"),
        json.as_bytes(),
    )
    .expect("write benchmark json artifact");
    std::fs::write(
        format!("{artifact_dir}/quickex-core-benchmarks.md"),
        markdown.as_bytes(),
    )
    .expect("write benchmark markdown artifact");
}

fn expected_escrow_entry(
    env: &Env,
    token: &Address,
    owner: &Address,
    amount: i128,
    status: EscrowStatus,
    expires_at: u64,
    arbiter: Option<Address>,
) -> EscrowEntry {
    EscrowEntry {
        token: token.clone(),
        amount_due: amount,
        amount_paid: amount,
        owner: owner.clone(),
        status,
        created_at: env.ledger().timestamp(),
        expires_at,
        arbiter,
        arbiters: Vec::new(env),
        arbiter_threshold: 0,
    }
}

fn legacy_privacy_storage_key(env: &Env, owner: &Address) -> (Symbol, Address) {
    (Symbol::new(env, PRIVACY_ENABLED_KEY), owner.clone())
}

fn print_storage_delta(label: &str, legacy_bytes: usize, compact_bytes: usize) {
    let saved = legacy_bytes.saturating_sub(compact_bytes);
    std::println!(
        "[bench] {label:<35}  legacy={legacy_bytes:<6} compact={compact_bytes:<6} saved={saved}"
    );
}

// ---------------------------------------------------------------------------
// Hot-path benchmarks
// ---------------------------------------------------------------------------

/// Benchmark: core lifecycle costs for create, fulfill, refund, and dispute.
/// Fails when a cost crosses its checked-in regression threshold.
#[test]
fn bench_core_lifecycle_costs() {
    let mut results: StdVec<CoreBenchResult> = StdVec::new();

    {
        let (env, client) = setup();
        let token = create_test_token(&env);
        let owner = Address::generate(&env);
        let salt = Bytes::from_slice(&env, b"bench_core_create");
        let amount: i128 = 1_000_000;
        let timeout_secs = 600u64;
        let arbiter = Some(Address::generate(&env));
        token::StellarAssetClient::new(&env, &token).mint(&owner, &amount);
        let commitment = make_commitment(&env, &owner, amount, &salt);
        let escrow_id = escrow_id::derive_escrow_id(
            &env,
            &token,
            amount,
            &owner,
            &salt,
            timeout_secs,
            &arbiter,
        )
        .expect("derive escrow id");
        let entry = expected_escrow_entry(
            &env,
            &token,
            &owner,
            amount,
            EscrowStatus::Pending,
            env.ledger().timestamp() + timeout_secs,
            arbiter.clone(),
        );
        let storage_fee_bytes = escrow_storage_fee_bytes(&env, &commitment, &entry)
            + escrow_id_storage_fee_bytes(&env, &escrow_id, &commitment);

        results.push(bench_core_op(
            &env,
            "create",
            storage_fee_bytes,
            500_000,
            100_000,
            1_000,
            || {
                client.deposit(&token, &amount, &owner, &salt, &timeout_secs, &arbiter);
            },
        ));
    }

    {
        let (env, client) = setup();
        let token = create_test_token(&env);
        let owner = Address::generate(&env);
        let salt = Bytes::from_slice(&env, b"bench_core_fulfill");
        let amount: i128 = 1_000_000;
        let commitment = make_commitment(&env, &owner, amount, &salt);
        seed_escrow(
            &env,
            &client.address,
            &token,
            &owner,
            amount,
            commitment.clone(),
        );
        token::StellarAssetClient::new(&env, &token).mint(&client.address, &amount);
        let entry =
            expected_escrow_entry(&env, &token, &owner, amount, EscrowStatus::Spent, 0, None);

        results.push(bench_core_op(
            &env,
            "fulfill",
            escrow_storage_fee_bytes(&env, &commitment, &entry),
            500_000,
            100_000,
            1_000,
            || {
                client.withdraw(&token, &amount, &commitment, &owner, &salt);
            },
        ));
    }

    {
        let (env, client) = setup();
        let token = create_test_token(&env);
        let owner = Address::generate(&env);
        let salt = Bytes::from_slice(&env, b"bench_core_refund");
        let amount: i128 = 1_000_000;
        let timeout_secs = 10u64;
        token::StellarAssetClient::new(&env, &token).mint(&owner, &amount);
        let commitment = client.deposit(&token, &amount, &owner, &salt, &timeout_secs, &None);
        env.ledger()
            .set_timestamp(env.ledger().timestamp() + timeout_secs);
        let entry = expected_escrow_entry(
            &env,
            &token,
            &owner,
            amount,
            EscrowStatus::Refunded,
            env.ledger().timestamp(),
            None,
        );

        results.push(bench_core_op(
            &env,
            "refund",
            escrow_storage_fee_bytes(&env, &commitment, &entry),
            500_000,
            100_000,
            1_000,
            || {
                client.refund(&commitment, &owner);
            },
        ));
    }

    {
        let (env, client) = setup();
        let token = create_test_token(&env);
        let owner = Address::generate(&env);
        let arbiter = Address::generate(&env);
        let salt = Bytes::from_slice(&env, b"bench_core_dispute");
        let amount: i128 = 1_000_000;
        token::StellarAssetClient::new(&env, &token).mint(&owner, &amount);
        let commitment = client.deposit(
            &token,
            &amount,
            &owner,
            &salt,
            &600u64,
            &Some(arbiter.clone()),
        );
        let entry = expected_escrow_entry(
            &env,
            &token,
            &owner,
            amount,
            EscrowStatus::Disputed,
            env.ledger().timestamp() + 600,
            Some(arbiter),
        );

        results.push(bench_core_op(
            &env,
            "dispute",
            escrow_storage_fee_bytes(&env, &commitment, &entry),
            500_000,
            100_000,
            1_000,
            || {
                client.dispute(&commitment);
            },
        ));
    }

    write_core_bench_artifacts(&results);
    for result in results {
        result.assert_within_threshold();
    }
}

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

/// Benchmark: SHA256 on the small commitment payload.
#[test]
fn bench_sha256_small_payload() {
    let (env, _) = setup();
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"bench_hash_small_payload");
    let payload = make_commitment_payload(&env, &owner, 1_000_000, &salt);

    env.cost_estimate().budget().reset_default();
    let _: BytesN<32> = env.crypto().sha256(&payload).into();
    print_budget(&env, "sha256_small_payload");
}

/// Benchmark: Keccak256 on the same small commitment payload.
#[test]
fn bench_keccak256_small_payload() {
    let (env, _) = setup();
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"bench_hash_small_payload");
    let payload = make_commitment_payload(&env, &owner, 1_000_000, &salt);

    env.cost_estimate().budget().reset_default();
    let _: BytesN<32> = env.crypto().keccak256(&payload).into();
    print_budget(&env, "keccak256_small_payload");
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
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);

    client.initialize(&admin);

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
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);

    client.initialize(&admin);
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
    let contract_id = env.register(QuickexContract, ());
    let owner = Address::generate(&env);
    let key = legacy_privacy_storage_key(&env, &owner);
    env.as_contract(&contract_id, || {
        env.storage().persistent().set(&key, &true);
    });

    env.cost_estimate().budget().reset_default();
    env.as_contract(&contract_id, || {
        let _: bool = env.storage().persistent().get(&key).unwrap_or(false);
    });
    print_budget(&env, "legacy_privacy_key_read");
}

/// Benchmark: typed privacy-key read
/// Measures the `DataKey::PrivacyEnabled` storage path used by privacy checks.
#[test]
fn bench_typed_privacy_key_read() {
    let env = Env::default();
    let contract_id = env.register(QuickexContract, ());
    let owner = Address::generate(&env);
    let key = DataKey::PrivacyEnabled(owner);
    env.as_contract(&contract_id, || {
        env.storage().persistent().set(&key, &true);
    });

    env.cost_estimate().budget().reset_default();
    env.as_contract(&contract_id, || {
        let _: bool = env.storage().persistent().get(&key).unwrap_or(false);
    });
    print_budget(&env, "typed_privacy_key_read");
}

/// Benchmark: legacy privacy-key write
/// Measures the pre-migration `(Symbol, Address)` storage write path directly.
#[test]
fn bench_legacy_privacy_key_write() {
    let env = Env::default();
    let contract_id = env.register(QuickexContract, ());
    let owner = Address::generate(&env);
    let key = legacy_privacy_storage_key(&env, &owner);

    env.cost_estimate().budget().reset_default();
    env.as_contract(&contract_id, || {
        env.storage().persistent().set(&key, &true);
    });
    print_budget(&env, "legacy_privacy_key_write");
}

/// Benchmark: typed privacy-key write
/// Measures the `DataKey::PrivacyEnabled` storage write path used by privacy toggles.
#[test]
fn bench_typed_privacy_key_write() {
    let env = Env::default();
    let contract_id = env.register(QuickexContract, ());
    let owner = Address::generate(&env);
    let key = DataKey::PrivacyEnabled(owner);

    env.cost_estimate().budget().reset_default();
    env.as_contract(&contract_id, || {
        env.storage().persistent().set(&key, &true);
    });
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

/// Benchmark: resolve_dispute (recipient path)
///
/// Captures the disputed-escrow settlement path when funds are awarded to a
/// recipient. This is the path optimized in issue #309 to minimize redundant
/// signature prompts.
#[test]
fn bench_resolve_dispute_recipient() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let owner = Address::generate(&env);
    let arbiter = Address::generate(&env);
    let recipient = Address::generate(&env);
    let amount: i128 = 1_000_000;
    let salt = Bytes::from_slice(&env, b"bench_salt_resolve_dispute");

    // Setup: create and dispute escrow — excluded from measurement.
    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&owner, &amount);
    let commitment = client.deposit(
        &token,
        &amount,
        &owner,
        &salt,
        &1000u64,
        &Some(arbiter.clone()),
    );
    client.dispute(&commitment);

    // --- Reset budget immediately before the hot path ---
    env.cost_estimate().budget().reset_default();
    client.resolve_dispute(&arbiter, &commitment, &false, &recipient);
    print_budget(&env, "resolve_dispute_recipient");
}

/// Benchmark: common escrow storage footprint before/after compaction.
///
/// Measures the serialized storage bytes for the typical no-arbiter escrow.
#[test]
fn bench_common_escrow_storage_footprint() {
    let env = Env::default();
    let commitment: Bytes = Bytes::from_array(&env, &[0x11; 32]);
    let entry = EscrowEntry {
        token: Address::generate(&env),
        amount_due: 1_000_000,
        amount_paid: 1_000_000,
        owner: Address::generate(&env),
        status: EscrowStatus::Pending,
        created_at: env.ledger().timestamp(),
        expires_at: 0,
        arbiter: None,
        arbiters: Vec::new(&env),
        arbiter_threshold: 0,
    };

    let legacy_bytes = legacy_escrow_storage_footprint_bytes(&env, &commitment, &entry);
    let compact_bytes = compact_escrow_storage_footprint_bytes(&env, &commitment, &entry);

    print_storage_delta("common_escrow_storage", legacy_bytes, compact_bytes);
    assert!(compact_bytes < legacy_bytes);
}

/// Benchmark: arbiter escrow storage footprint before/after compaction.
///
/// Documents the tradeoff for less-common escrows that opt into dispute config.
#[test]
fn bench_arbiter_escrow_storage_footprint() {
    let env = Env::default();
    let commitment: Bytes = Bytes::from_array(&env, &[0x22; 32]);
    let entry = EscrowEntry {
        token: Address::generate(&env),
        amount_due: 1_000_000,
        amount_paid: 1_000_000,
        owner: Address::generate(&env),
        status: EscrowStatus::Pending,
        created_at: env.ledger().timestamp(),
        expires_at: 0,
        arbiter: Some(Address::generate(&env)),
        arbiters: Vec::new(&env),
        arbiter_threshold: 0,
    };

    let legacy_bytes = legacy_escrow_storage_footprint_bytes(&env, &commitment, &entry);
    let compact_bytes = compact_escrow_storage_footprint_bytes(&env, &commitment, &entry);

    print_storage_delta("arbiter_escrow_storage", legacy_bytes, compact_bytes);
}
