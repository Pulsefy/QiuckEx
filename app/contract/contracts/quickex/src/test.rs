#![cfg(test)]
use crate::{EscrowEntry, EscrowStatus, QuickexContract, QuickexContractClient};
use soroban_sdk::{Address, Bytes, BytesN, Env, testutils::Address as _, token, xdr::ToXdr};

fn setup<'a>() -> (Env, QuickexContractClient<'a>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    (env, client)
}

fn setup_escrow(
    env: &Env,
    contract_id: &Address,
    token: &Address,
    amount: i128,
    commitment: BytesN<32>,
) {
    let depositor = Address::generate(env);

    let entry = EscrowEntry {
        commitment: commitment.clone(),
        token: token.clone(),
        amount,
        status: EscrowStatus::Pending,
        depositor,
    };

    let escrow_key = soroban_sdk::Symbol::new(env, "escrow");

    env.as_contract(contract_id, || {
        env.storage()
            .persistent()
            .set(&(escrow_key, commitment), &entry);
    });
}

fn create_test_token(env: &Env) -> Address {
    env.register_stellar_asset_contract_v2(Address::generate(env))
        .address()
}

#[test]
fn test_successful_withdrawal() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"test_salt_123");

    let mut data = Bytes::new(&env);

    let address_bytes: Bytes = to.clone().to_xdr(&env);

    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);

    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(&env, &client.address, &token, amount, commitment);

    env.mock_all_auths();

    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&client.address, &amount);

    let _ = client.withdraw(&to, &amount, &salt);
}

#[test]
#[should_panic]
fn test_double_withdrawal_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"test_salt_456");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = to.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(&env, &client.address, &token, amount, commitment.clone());

    env.mock_all_auths();

    let token_client = token::StellarAssetClient::new(&env, &token);
    token_client.mint(&client.address, &(amount * 2));

    let first_result = client.try_withdraw(&to, &amount, &salt);
    assert!(first_result.is_ok());
    assert_eq!(first_result.unwrap(), Ok(true));
    let _ = client.withdraw(&to, &amount, &salt);
}

#[test]
#[should_panic]
fn test_invalid_salt_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let amount: i128 = 1000;
    let correct_salt = Bytes::from_slice(&env, b"correct_salt");
    let wrong_salt = Bytes::from_slice(&env, b"wrong_salt");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = to.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &amount.to_be_bytes()));
    data.append(&correct_salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(&env, &client.address, &token, amount, commitment.clone());

    env.mock_all_auths();
    let _ = client.withdraw(&to, &amount, &wrong_salt);
}

#[test]
#[should_panic]
fn test_invalid_amount_fails() {
    let (env, client) = setup();
    let token = create_test_token(&env);
    let to = Address::generate(&env);
    let correct_amount: i128 = 1000;
    let wrong_amount: i128 = 500;
    let salt = Bytes::from_slice(&env, b"test_salt_789");

    let mut data = Bytes::new(&env);
    let address_bytes: Bytes = to.clone().to_xdr(&env);
    data.append(&address_bytes);
    data.append(&Bytes::from_slice(&env, &correct_amount.to_be_bytes()));
    data.append(&salt);
    let commitment: BytesN<32> = env.crypto().sha256(&data).into();

    setup_escrow(
        &env,
        &client.address,
        &token,
        correct_amount,
        commitment.clone(),
    );

    env.mock_all_auths();

    let _ = client.withdraw(&to, &wrong_amount, &salt);
}

#[test]
#[should_panic]
fn test_zero_amount_fails() {
    let (env, client) = setup();
    let to = Address::generate(&env);
    let amount: i128 = 0;
    let salt = Bytes::from_slice(&env, b"test_salt");

    env.mock_all_auths();

    let _ = client.withdraw(&to, &amount, &salt);
}

#[test]
#[should_panic]
fn test_negative_amount_fails() {
    let (env, client) = setup();
    let to = Address::generate(&env);
    let amount: i128 = -100;
    let salt = Bytes::from_slice(&env, b"test_salt");

    env.mock_all_auths();

    let _ = client.withdraw(&to, &amount, &salt);
}

#[test]
#[should_panic]
fn test_nonexistent_commitment_fails() {
    let (env, client) = setup();
    let to = Address::generate(&env);
    let amount: i128 = 1000;
    let salt = Bytes::from_slice(&env, b"nonexistent");

    env.mock_all_auths();
    let _ = client.withdraw(&to, &amount, &salt);
}

#[test]
fn test_set_and_get_privacy() {
    let (env, client) = setup();
    let account = Address::generate(&env);

    // Default should be false
    assert!(!client.get_privacy(&account));

    // Enable privacy
    client.set_privacy(&account, &true);
    assert!(client.get_privacy(&account));

    // Disable privacy
    client.set_privacy(&account, &false);
    assert!(!client.get_privacy(&account));
}

#[test]
fn test_commitment_cycle() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount = 1_000_000i128;
    let mut salt = Bytes::new(&env);
    salt.append(&Bytes::from_slice(&env, b"random_salt"));

    // Create commitment
    let commitment = client.create_amount_commitment(&owner, &amount, &salt);

    // Verify correct commitment
    let is_valid = client.verify_amount_commitment(&commitment, &owner, &amount, &salt);
    assert!(is_valid);

    // Verify incorrect amount
    let is_valid_bad_amount =
        client.verify_amount_commitment(&commitment, &owner, &2_000_000i128, &salt);
    assert!(!is_valid_bad_amount);

    // Verify incorrect salt
    let mut bad_salt = Bytes::new(&env);
    bad_salt.append(&Bytes::from_slice(&env, b"wrong_salt"));
    let is_valid_bad_salt =
        client.verify_amount_commitment(&commitment, &owner, &amount, &bad_salt);
    assert!(!is_valid_bad_salt);
}

#[test]
fn test_create_escrow() {
    let (env, client) = setup();
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    let amount = 1_000;
    let escrow_id = client.create_escrow(&from, &to, &amount);
    assert!(escrow_id > 0);
}

#[test]
fn test_health_check() {
    let (_, client) = setup();
    assert!(client.health_check());
}

#[test]
fn test_deposit() {
    let env = Env::default();
    env.mock_all_auths();

    let user = Address::generate(&env);
    let token_admin = Address::generate(&env);

    let token_id = env.register_stellar_asset_contract_v2(token_admin.clone()).address();
    let token_client = token::StellarAssetClient::new(&env, &token_id);

    token_client.mint(&user, &1000);

    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);

    let commitment = BytesN::from_array(&env, &[1; 32]);

    client.deposit(
        &user,
        &token_id,
        &500,
        &commitment,
    );

    assert_eq!(token_client.balance(&user), 500);
    assert_eq!(
        token_client.balance(&contract_id),
        500
    );
}
