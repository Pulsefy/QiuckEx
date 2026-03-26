use crate::{types::FeeConfig, QuickexContract, QuickexContractClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, Bytes, Env,
};

fn setup_test(
    env: &Env,
) -> (
    QuickexContractClient<'_>,
    Address,
    Address,
    Address,
    Address,
) {
    let admin = Address::generate(env);
    let platform_wallet = Address::generate(env);
    let owner = Address::generate(env);
    let recipient = Address::generate(env);

    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(env, &contract_id);

    client.initialize(&admin);

    (client, admin, platform_wallet, owner, recipient)
}

#[test]
fn test_fee_admin() {
    let env = Env::default();
    let (client, admin, platform_wallet, _, _) = setup_test(&env);

    env.mock_all_auths();

    // Set fee config
    let fee_config = FeeConfig { fee_bps: 250 }; // 2.5%
    client.set_fee_config(&admin, &fee_config);

    assert_eq!(client.get_fee_config().fee_bps, 250);

    // Set platform wallet
    client.set_platform_wallet(&admin, &platform_wallet);
    assert_eq!(client.get_platform_wallet(), Some(platform_wallet));
}

#[test]
fn test_withdrawal_with_fee() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let (client, admin, platform_wallet, owner, _recipient) = setup_test(&env);

    // Setup token
    let token_admin = Address::generate(&env);
    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_id);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

    env.mock_all_auths();

    token_admin_client.mint(&owner, &10000);

    // Configure fees
    client.set_fee_config(&admin, &FeeConfig { fee_bps: 1000 }); // 10%
    client.set_platform_wallet(&admin, &platform_wallet);

    // Deposit
    let amount = 1000i128;
    let salt = Bytes::from_array(&env, &[1; 32]);
    let commitment = client.deposit(&token_id, &amount, &owner, &salt, &3600, &None);

    assert_eq!(token_client.balance(&owner), 9000);
    assert_eq!(token_client.balance(&client.address), 1000);

    // Withdraw (payout to recipient)
    // Salt must match the one used during deposit.
    // Commitment is recomputed from recipient, amount, and salt.
    // Wait, the commitment is recomputed from recipient during withdrawal in `escrow::withdraw`.
    // So the recipient must be the one whose address was used to create the commitment.
    // In `QuickexContract::deposit`, the commitment is created using `owner`.
    // Wait, let's check `escrow::deposit`:
    // `let commitment = commitment::create_amount_commitment(env, owner.clone(), amount, salt)?;`
    // And `escrow::withdraw`:
    // `let commitment = commitment::create_amount_commitment(env, to.clone(), amount, salt)?;`
    // This means the `owner` in `deposit` is the RECIPIENT who can withdraw.
    // Let me re-read `deposit`.
    // `pub fn deposit(..., owner: Address, salt: Bytes, ...)`
    // The `owner` is the one who can authorize the transfer AND whose address is in the commitment.
    // So if Alice deposits for Bob, Bob's address should be used in the commitment if Bob is to withdraw.
    // But `deposit` takes `amount` FROM `owner`.
    // Let's re-verify:
    // `owner.require_auth(); ... token_client.transfer(&owner, env.current_contract_address(), &amount);`
    // So `owner` is the depositor. And `withdraw` uses `to.require_auth()` and checks the commitment with `to`.
    // This means by default, only the depositor can withdraw to themselves using the commitment.
    // If they want someone else to withdraw, they'd need a different flow or use a different address in the commitment.
    // Actually, the commitment is `SHA256(owner || amount || salt)`.
    // If Alice deposits, the commitment is `SHA256(Alice || amount || salt)`. Only Alice can withdraw using this commitment.

    // Let's proceed with Alice (owner) withdrawing to herself.
    client.withdraw(&token_id, &amount, &commitment, &owner, &salt);

    // Fee is 10% of 1000 = 100.
    // Alice should get 1000 - 100 = 900.
    // Total balance for Alice: 9000 + 900 = 9900.
    assert_eq!(token_client.balance(&owner), 9900);
    assert_eq!(token_client.balance(&platform_wallet), 100);
    assert_eq!(token_client.balance(&client.address), 0);
}

#[test]
fn test_zero_fee() {
    let env = Env::default();
    let (client, admin, platform_wallet, owner, _) = setup_test(&env);

    let token_admin = Address::generate(&env);
    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_id);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_id);

    env.mock_all_auths();

    token_admin_client.mint(&owner, &10000);

    // 0 Fee bps
    client.set_fee_config(&admin, &FeeConfig { fee_bps: 0 });
    client.set_platform_wallet(&admin, &platform_wallet);

    let amount = 1000i128;
    let salt = Bytes::from_array(&env, &[1; 32]);
    let commitment = client.deposit(&token_id, &amount, &owner, &salt, &3600, &None);

    client.withdraw(&token_id, &amount, &commitment, &owner, &salt);

    assert_eq!(token_client.balance(&owner), 10000);
    assert_eq!(token_client.balance(&platform_wallet), 0);
}
