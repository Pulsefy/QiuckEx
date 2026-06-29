//! Pause Policy v1 tests – normal, global pause, and emergency mode matrix.

use crate::{
    errors::QuickexError,
    pause_policy::{EntryPoint, PauseChangeReason},
    storage::PauseFlag,
    types::StealthDepositParams,
    EscrowStatus, QuickexContract, QuickexContractClient,
};
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger},
    token,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, InvokeError, Map, Symbol, TryIntoVal, Val,
};

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

fn assert_contract_error<T>(
    result: Result<Result<T, soroban_sdk::ConversionError>, Result<QuickexError, InvokeError>>,
    expected: QuickexError,
) {
    match result {
        Err(Ok(actual)) => assert_eq!(actual, expected),
        _ => panic!("expected contract error"),
    }
}

fn setup_expired_refund_escrow(
    env: &Env,
    client: &QuickexContractClient,
    token: &Address,
    owner: &Address,
    amount: i128,
) -> BytesN<32> {
    let salt = Bytes::from_slice(env, b"pause_policy_refund_salt");
    let timeout = 100u64;
    token::StellarAssetClient::new(env, token).mint(owner, &amount);
    let commitment = client.deposit(token, &amount, owner, &salt, &timeout, &None);
    let expires_at = env.ledger().timestamp() + timeout;
    env.ledger().set_timestamp(expires_at);
    commitment
}

fn setup_withdrawable_escrow(
    env: &Env,
    client: &QuickexContractClient,
    token: &Address,
    recipient: &Address,
    amount: i128,
) -> (BytesN<32>, Bytes) {
    let salt = Bytes::from_slice(env, b"pause_policy_withdraw_salt");
    let mut data = Bytes::new(env);
    data.append(&recipient.clone().to_xdr(env));
    data.append(&Bytes::from_slice(env, &amount.to_be_bytes()));
    data.append(&salt.clone());
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    let entry = crate::EscrowEntry {
        token: token.clone(),
        amount_due: amount,
        amount_paid: amount,
        owner: recipient.clone(),
        status: EscrowStatus::Pending,
        created_at: env.ledger().timestamp(),
        expires_at: 0,
        arbiter: None,
        arbiters: soroban_sdk::Vec::new(env),
        arbiter_threshold: 0,
    };
    env.as_contract(&client.address, || {
        crate::storage::put_escrow(env, &commitment.clone().into(), &entry);
    });
    token::StellarAssetClient::new(env, token).mint(&client.address, &amount);
    (commitment, salt)
}

#[test]
fn test_emergency_allowlist_includes_fund_recovery_paths() {
    let (_env, client) = setup();

    assert!(client.is_entry_allowed_in_emergency(&EntryPoint::Withdraw));
    assert!(client.is_entry_allowed_in_emergency(&EntryPoint::Refund));
    assert!(client.is_entry_allowed_in_emergency(&EntryPoint::StealthWithdraw));
    assert!(client.is_entry_allowed_in_emergency(&EntryPoint::CleanupEscrow));
    assert!(!client.is_entry_allowed_in_emergency(&EntryPoint::Deposit));
    assert!(!client.is_entry_allowed_in_emergency(&EntryPoint::DepositWithCommitment));
}

#[test]
fn test_risky_entry_points_blocked_in_emergency_mode() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let token = create_test_token(&env);
    let amount: i128 = 1_000;

    client.initialize(&admin);
    client.activate_emergency_mode(&admin);
    assert!(client.is_emergency_mode());

    token::StellarAssetClient::new(&env, &token).mint(&user, &amount);
    let salt = Bytes::from_slice(&env, b"emergency_deposit_salt");

    assert_contract_error(
        client.try_deposit(&token, &amount, &user, &salt, &0u64, &None),
        QuickexError::ContractPaused,
    );

    let commitment = BytesN::from_array(&env, &[9u8; 32]);
    assert_contract_error(
        client.try_deposit_with_commitment(&user, &token, &amount, &commitment, &0, &None),
        QuickexError::ContractPaused,
    );

    assert_contract_error(
        client.try_deposit_partial(&token, &amount, &500, &user, &salt, &0, &None),
        QuickexError::ContractPaused,
    );

    assert_contract_error(
        client.try_partial_payment(&commitment, &user, &100),
        QuickexError::ContractPaused,
    );

    assert_contract_error(
        client.try_dispute(&commitment),
        QuickexError::ContractPaused,
    );

    assert_contract_error(
        client.try_set_privacy(&user, &true),
        QuickexError::ContractPaused,
    );

    assert_contract_error(
        client.try_set_paused(&admin, &true),
        QuickexError::ContractPaused,
    );
}

#[test]
fn test_safe_entry_points_remain_usable_in_emergency_mode() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token = create_test_token(&env);
    let amount: i128 = 1_000;

    client.initialize(&admin);

    let refund_commitment = setup_expired_refund_escrow(&env, &client, &token, &owner, amount);
    let (withdraw_commitment, withdraw_salt) =
        setup_withdrawable_escrow(&env, &client, &token, &recipient, amount);

    client.activate_emergency_mode(&admin);
    env.mock_all_auths();

    client.refund(&refund_commitment, &owner);
    client.withdraw(
        &token,
        &amount,
        &withdraw_commitment,
        &recipient,
        &withdraw_salt,
    );
    let _ = client.try_cleanup_escrow(&refund_commitment).unwrap();
    let _ = client.try_extend_escrow_ttl(&withdraw_commitment).unwrap();
}

#[test]
fn test_global_pause_blocks_all_non_view_entry_points() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token = create_test_token(&env);
    let amount: i128 = 1_000;

    client.initialize(&admin);

    let refund_commitment = setup_expired_refund_escrow(&env, &client, &token, &owner, amount);
    let (withdraw_commitment, withdraw_salt) =
        setup_withdrawable_escrow(&env, &client, &token, &recipient, amount);

    client.set_paused(&admin, &true);

    token::StellarAssetClient::new(&env, &token).mint(&owner, &amount);
    let salt = Bytes::from_slice(&env, b"global_pause_salt");
    assert_contract_error(
        client.try_deposit(&token, &amount, &owner, &salt, &0u64, &None),
        QuickexError::ContractPaused,
    );

    assert_contract_error(
        client.try_refund(&refund_commitment, &owner),
        QuickexError::ContractPaused,
    );

    assert_contract_error(
        client.try_withdraw(
            &token,
            &amount,
            &withdraw_commitment,
            &recipient,
            &withdraw_salt,
        ),
        QuickexError::ContractPaused,
    );
}

#[test]
fn test_feature_pause_blocks_only_targeted_entry_points() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let token = create_test_token(&env);
    let amount: i128 = 1_000;

    client.initialize(&admin);

    let refund_commitment = setup_expired_refund_escrow(&env, &client, &token, &owner, amount);

    client.pause_features(&admin, &(PauseFlag::Deposit as u64));

    token::StellarAssetClient::new(&env, &token).mint(&owner, &amount);
    let salt = Bytes::from_slice(&env, b"feature_pause_salt");
    assert_contract_error(
        client.try_deposit(&token, &amount, &owner, &salt, &0u64, &None),
        QuickexError::OperationPaused,
    );

    env.mock_all_auths();
    client.refund(&refund_commitment, &owner);
}

#[test]
fn test_emergency_mode_blocks_stealth_deposit_but_allows_withdraw() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token = create_test_token(&env);
    let amount: i128 = 500;

    let eph_pub = BytesN::from_array(&env, &[3u8; 32]);
    let spend_pub = BytesN::from_array(&env, &[4u8; 32]);
    let shared = crate::stealth::derive_shared_secret(&env, &eph_pub, &spend_pub);
    let stealth_address = crate::stealth::derive_stealth_address(&env, &spend_pub, &shared);

    client.initialize(&admin);
    token::StellarAssetClient::new(&env, &token).mint(&sender, &amount);

    let params = StealthDepositParams {
        sender: sender.clone(),
        token: token.clone(),
        amount_due: amount,
        amount_paid: amount,
        eph_pub: eph_pub.clone(),
        spend_pub: spend_pub.clone(),
        stealth_address: stealth_address.clone(),
        timeout_secs: 0,
    };

    client.register_ephemeral_key(&params);
    client.activate_emergency_mode(&admin);

    let blocked_params = StealthDepositParams {
        sender,
        token: token.clone(),
        amount_due: amount,
        amount_paid: amount,
        eph_pub: BytesN::from_array(&env, &[5u8; 32]),
        spend_pub: BytesN::from_array(&env, &[6u8; 32]),
        stealth_address: BytesN::from_array(&env, &[7u8; 32]),
        timeout_secs: 0,
    };
    assert_contract_error(
        client.try_register_ephemeral_key(&blocked_params),
        QuickexError::ContractPaused,
    );

    env.mock_all_auths();
    client.stealth_withdraw(&recipient, &eph_pub, &spend_pub, &stealth_address);
}

fn latest_contract_event(env: &Env, contract_id: &Address) -> (soroban_sdk::Vec<Val>, Val) {
    let all = env.events().all();
    for i in (0..all.len()).rev() {
        let event = all.get(i).unwrap();
        if event.0 == *contract_id {
            return (event.1, event.2);
        }
    }
    panic!("no contract event found");
}

fn event_data_map(env: &Env, data: Val) -> Map<Symbol, Val> {
    data.try_into_val(env).unwrap()
}

#[test]
fn test_pause_events_include_reason_fields() {
    let (env, client) = setup();
    let admin = Address::generate(&env);

    client.initialize(&admin);
    client.set_paused(&admin, &true);

    let (topics, data) = latest_contract_event(&env, &client.address);
    let t1: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(t1, Symbol::new(&env, "ContractPaused"));

    let data_map = event_data_map(&env, data);
    let reason: u32 = data_map
        .get(Symbol::new(&env, "reason"))
        .unwrap()
        .try_into_val(&env)
        .unwrap();
    assert_eq!(reason, PauseChangeReason::GlobalPause as u32);

    client.pause_features(&admin, &(PauseFlag::Refund as u64));
    let (topics, data) = latest_contract_event(&env, &client.address);
    let t1: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(t1, Symbol::new(&env, "PauseFlagsChanged"));

    let data_map = event_data_map(&env, data);
    let reason: u32 = data_map
        .get(Symbol::new(&env, "reason"))
        .unwrap()
        .try_into_val(&env)
        .unwrap();
    assert_eq!(reason, PauseChangeReason::FeatureFlagsUpdated as u32);
    let flags: u64 = data_map
        .get(Symbol::new(&env, "flags"))
        .unwrap()
        .try_into_val(&env)
        .unwrap();
    assert_eq!(flags, PauseFlag::Refund as u64);
}

#[test]
fn test_emergency_mode_blocks_risky_entry_points_and_allows_safe_paths() {
    let (env, client) = setup();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let token = create_test_token(&env);
    let amount: i128 = 1000;

    client.initialize(&admin);
    let commitment = setup_expired_refund_escrow(&env, &client, &token, &user, amount);

    client.activate_emergency_mode(&admin);

    let salt = BytesN::from_array(&env, &[0u8; 32]);
    let salt_bytes: Bytes = salt.into();
    assert_contract_error(
        client.try_deposit(&token, &amount, &user, &salt_bytes, &0u64, &None),
        QuickexError::ContractPaused,
    );

    env.mock_all_auths();
    client.refund(&commitment, &user);
    let _ = client.try_cleanup_escrow(&commitment).unwrap();
}
