//! Receipt reference determinism tests (SC-W7-07).
//!
//! Verifies that the receipt references emitted in create, release, and
//! refund-related contract events are deterministic, stable across ledger
//! time, and action/escrow specific.

use crate::{
    events::{
        generate_receipt_reference, RECEIPT_REF_ACTION_DEPOSIT, RECEIPT_REF_ACTION_FINALIZE,
        RECEIPT_REF_ACTION_REFUND, RECEIPT_REF_ACTION_REFUND_FINALIZED,
        RECEIPT_REF_ACTION_WITHDRAW,
    },
    QuickexContract, QuickexContractClient,
};

use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger},
    token, Address, Bytes, BytesN, Env, Map, Symbol, TryIntoVal, Val, Vec,
};

fn latest_contract_event(env: &Env, contract_id: &Address) -> (Vec<Val>, Val) {
    let all = env.events().all();
    let len = all.len();

    extern crate std;
    let expected_str = std::format!("{:?}", contract_id);

    for i in (0..len).rev() {
        let event = all.get(i).unwrap();
        if std::format!("{:?}", event.0) == expected_str {
            return (event.1, event.2);
        }
    }

    panic!("no contract event found for contract id")
}

fn event_data_map(env: &Env, data: Val) -> Map<Symbol, Val> {
    data.try_into_val(env).unwrap()
}

fn receipt_reference_from_event(env: &Env, data: Val) -> BytesN<32> {
    event_data_map(env, data)
        .get(Symbol::new(env, "receipt_reference"))
        .expect("receipt_reference payload key present")
        .try_into_val(env)
        .unwrap()
}

fn setup<'a>() -> (Env, Address, QuickexContractClient<'a>) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let token_id = env.register_stellar_asset_contract_v2(admin).address();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    (env, token_id, client)
}

fn mint(env: &Env, token_id: &Address, to: &Address, amount: i128) {
    token::StellarAssetClient::new(env, token_id).mint(to, &amount);
}

#[test]
fn test_receipt_reference_is_deterministic_across_ledger_time() {
    let env = Env::default();
    let escrow_id = BytesN::from_array(&env, &[1; 32]);

    env.ledger().set_timestamp(1_000);
    let first = generate_receipt_reference(&env, &escrow_id, RECEIPT_REF_ACTION_DEPOSIT);

    env.ledger().set_timestamp(9_999_999);
    let second = generate_receipt_reference(&env, &escrow_id, RECEIPT_REF_ACTION_DEPOSIT);

    assert_eq!(
        first, second,
        "receipt reference must not depend on ledger time"
    );
}

#[test]
fn test_receipt_reference_differs_by_action() {
    let env = Env::default();
    let escrow_id = BytesN::from_array(&env, &[2; 32]);

    let deposit = generate_receipt_reference(&env, &escrow_id, RECEIPT_REF_ACTION_DEPOSIT);
    let withdraw = generate_receipt_reference(&env, &escrow_id, RECEIPT_REF_ACTION_WITHDRAW);
    let refund = generate_receipt_reference(&env, &escrow_id, RECEIPT_REF_ACTION_REFUND);
    let refund_finalized =
        generate_receipt_reference(&env, &escrow_id, RECEIPT_REF_ACTION_REFUND_FINALIZED);
    let finalize = generate_receipt_reference(&env, &escrow_id, RECEIPT_REF_ACTION_FINALIZE);

    let refs = [deposit, withdraw, refund, refund_finalized, finalize];
    for i in 0..refs.len() {
        for j in (i + 1)..refs.len() {
            assert_ne!(
                refs[i], refs[j],
                "different actions must produce different receipt references"
            );
        }
    }
}

#[test]
fn test_receipt_reference_differs_by_escrow() {
    let env = Env::default();
    let escrow_a = BytesN::from_array(&env, &[3; 32]);
    let escrow_b = BytesN::from_array(&env, &[4; 32]);

    let ref_a = generate_receipt_reference(&env, &escrow_a, RECEIPT_REF_ACTION_DEPOSIT);
    let ref_b = generate_receipt_reference(&env, &escrow_b, RECEIPT_REF_ACTION_DEPOSIT);

    assert_ne!(
        ref_a, ref_b,
        "different escrows must produce different references"
    );
}

#[test]
fn test_deposit_event_emits_deterministic_receipt_reference() {
    let (env, token_id, client) = setup();
    let owner = Address::generate(&env);
    mint(&env, &token_id, &owner, 1000);

    let salt = Bytes::from_slice(&env, b"rr_deposit_salt");
    let commitment = client.deposit(
        &token_id,
        &1000,
        &owner,
        &salt,
        &0u64,
        &None,
        &0u64,
        &u64::MAX,
    );

    let (topics, data) = latest_contract_event(&env, &client.address);
    let event_name: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(event_name, Symbol::new(&env, "EscrowDeposited"));

    let actual = receipt_reference_from_event(&env, data);
    let expected = generate_receipt_reference(&env, &commitment, RECEIPT_REF_ACTION_DEPOSIT);
    assert_eq!(actual, expected);
}

#[test]
fn test_withdraw_event_emits_deterministic_receipt_reference() {
    let (env, token_id, client) = setup();
    let owner = Address::generate(&env);
    mint(&env, &token_id, &owner, 1000);

    let salt = Bytes::from_slice(&env, b"rr_withdraw_salt");
    let commitment = client.deposit(
        &token_id,
        &1000,
        &owner,
        &salt,
        &0u64,
        &None,
        &0u64,
        &u64::MAX,
    );

    let _ = client.withdraw(
        &token_id,
        &1000,
        &commitment,
        &owner,
        &salt,
        &0u64,
        &u64::MAX,
    );

    let (topics, data) = latest_contract_event(&env, &client.address);
    let event_name: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(event_name, Symbol::new(&env, "EscrowWithdrawn"));

    let actual = receipt_reference_from_event(&env, data);
    let expected = generate_receipt_reference(&env, &commitment, RECEIPT_REF_ACTION_WITHDRAW);
    assert_eq!(actual, expected);
}

#[test]
fn test_refund_event_emits_deterministic_receipt_reference() {
    let (env, token_id, client) = setup();
    let owner = Address::generate(&env);
    mint(&env, &token_id, &owner, 1000);

    let timeout = 100u64;
    let salt = Bytes::from_slice(&env, b"rr_refund_salt");
    let commitment = client.deposit(
        &token_id,
        &1000,
        &owner,
        &salt,
        &timeout,
        &None,
        &0u64,
        &u64::MAX,
    );

    env.ledger()
        .set_timestamp(env.ledger().timestamp() + timeout + 1);
    client.refund(&commitment, &owner, &0u64, &u64::MAX);

    let (topics, data) = latest_contract_event(&env, &client.address);
    let event_name: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(event_name, Symbol::new(&env, "EscrowRefunded"));

    let actual = receipt_reference_from_event(&env, data);
    let expected = generate_receipt_reference(&env, &commitment, RECEIPT_REF_ACTION_REFUND);
    assert_eq!(actual, expected);
}

#[test]
fn test_refund_finalized_event_emits_deterministic_receipt_reference() {
    let (env, token_id, client) = setup();
    let owner = Address::generate(&env);
    mint(&env, &token_id, &owner, 1000);

    let timeout = 100u64;
    let salt = Bytes::from_slice(&env, b"rr_refund_finalized_salt");
    let commitment = client.deposit(
        &token_id,
        &1000,
        &owner,
        &salt,
        &timeout,
        &None,
        &0u64,
        &u64::MAX,
    );

    env.ledger()
        .set_timestamp(env.ledger().timestamp() + timeout + 1);
    client.finalize_expired_escrow(&commitment);

    let (topics, data) = latest_contract_event(&env, &client.address);
    let event_name: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(event_name, Symbol::new(&env, "RefundFinalized"));

    let actual = receipt_reference_from_event(&env, data);
    let expected =
        generate_receipt_reference(&env, &commitment, RECEIPT_REF_ACTION_REFUND_FINALIZED);
    assert_eq!(actual, expected);
}

#[test]
fn test_finalized_event_emits_deterministic_receipt_reference() {
    let (env, token_id, client) = setup();
    let owner = Address::generate(&env);
    let payer = Address::generate(&env);
    mint(&env, &token_id, &owner, 700);
    mint(&env, &token_id, &payer, 300);

    let salt = Bytes::from_slice(&env, b"rr_finalize_salt");
    let commitment = client.deposit_partial(
        &token_id,
        &1000,
        &700,
        &owner,
        &salt,
        &0u64,
        &None,
        &0u64,
        &u64::MAX,
    );

    client.partial_payment(&commitment, &payer, &300, &0u64, &u64::MAX);

    let (topics, data) = latest_contract_event(&env, &client.address);
    let event_name: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(event_name, Symbol::new(&env, "EscrowFinalized"));

    let actual = receipt_reference_from_event(&env, data);
    let expected = generate_receipt_reference(&env, &commitment, RECEIPT_REF_ACTION_FINALIZE);
    assert_eq!(actual, expected);
}
