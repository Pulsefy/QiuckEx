use crate::{types::PerAssetFeeConfig, EscrowStatus, QuickexContract, QuickexContractClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, Bytes, Env,
};

fn setup<'a>() -> (Env, QuickexContractClient<'a>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|li| li.timestamp = 1_000);

    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    (env, client, admin)
}

fn create_token(env: &Env) -> Address {
    env.register_stellar_asset_contract_v2(Address::generate(env))
        .address()
}

#[test]
fn test_fee_router_per_asset_overrides_global_across_assets() {
    let (env, client, admin) = setup();

    // "XLM" and "SAC" are both represented as token contract addresses in Soroban.
    let xlm_token = create_token(&env);
    let sac_token = create_token(&env);

    let user = Address::generate(&env);
    let collector = Address::generate(&env);

    let xlm_admin = token::StellarAssetClient::new(&env, &xlm_token);
    let sac_admin = token::StellarAssetClient::new(&env, &sac_token);
    let xlm_client = token::Client::new(&env, &xlm_token);
    let sac_client = token::Client::new(&env, &sac_token);

    xlm_admin.mint(&user, &10_000);
    sac_admin.mint(&user, &10_000);

    // Global fee = 5%.
    client.set_fee_config(&admin, &crate::types::FeeConfig { fee_bps: 500 });
    client.set_platform_wallet(&admin, &collector);

    // Per-asset override for XLM token = 10%.
    client.set_per_asset_fee(
        &admin,
        &xlm_token,
        &PerAssetFeeConfig {
            fee_bps: 1_000,
            arbiter_bps: 0,
        },
    );

    // Withdraw XLM path: fee should use per-asset 10%.
    let xlm_amount: i128 = 1_000;
    let xlm_salt = Bytes::from_slice(&env, b"fee_router_xlm_salt");
    let xlm_commitment = client.deposit(&xlm_token, &xlm_amount, &user, &xlm_salt, &0, &None);
    client.withdraw(&xlm_token, &xlm_amount, &xlm_commitment, &user, &xlm_salt);

    // Withdraw SAC path: fee should use global 5%.
    let sac_amount: i128 = 1_000;
    let sac_salt = Bytes::from_slice(&env, b"fee_router_sac_salt");
    let sac_commitment = client.deposit(&sac_token, &sac_amount, &user, &sac_salt, &0, &None);
    client.withdraw(&sac_token, &sac_amount, &sac_commitment, &user, &sac_salt);

    // Expected fees: XLM 100 + SAC 50 = 150 to collector.
    assert_eq!(xlm_client.balance(&collector), 100);
    assert_eq!(sac_client.balance(&collector), 50);

    // User received net payout per token and no escrow balance remains in contract.
    assert_eq!(xlm_client.balance(&client.address), 0);
    assert_eq!(sac_client.balance(&client.address), 0);

    // Sanity check statuses are terminal and correct.
    assert_eq!(
        client.get_commitment_state(&xlm_commitment),
        Some(EscrowStatus::Spent)
    );
    assert_eq!(
        client.get_commitment_state(&sac_commitment),
        Some(EscrowStatus::Spent)
    );
}

#[test]
fn test_fee_router_dispute_with_optional_arbiter_split() {
    let (env, client, admin) = setup();

    let token_id = create_token(&env);
    let owner = Address::generate(&env);
    let recipient = Address::generate(&env);
    let arbiter = Address::generate(&env);
    let collector = Address::generate(&env);

    let token_admin = token::StellarAssetClient::new(&env, &token_id);
    let token_client = token::Client::new(&env, &token_id);

    token_admin.mint(&owner, &10_000);

    client.set_platform_wallet(&admin, &collector);
    client.set_per_asset_fee(
        &admin,
        &token_id,
        &PerAssetFeeConfig {
            fee_bps: 1_000,     // 10% total fee
            arbiter_bps: 2_000, // 20% of fee to arbiter
        },
    );

    let amount: i128 = 1_000;
    let salt = Bytes::from_slice(&env, b"fee_router_dispute_split");
    let commitment = client.deposit(
        &token_id,
        &amount,
        &owner,
        &salt,
        &1000,
        &Some(arbiter.clone()),
    );

    client.dispute(&commitment);
    client.resolve_dispute(&arbiter, &commitment, &false, &recipient);

    // Fee math:
    // total_fee = 100
    // arbiter_fee = 20
    // collector_fee = 80
    // recipient_net = 900
    assert_eq!(token_client.balance(&recipient), 900);
    assert_eq!(token_client.balance(&arbiter), 20);
    assert_eq!(token_client.balance(&collector), 80);

    // Bound safety: payout + arbiter + collector equals gross amount.
    assert_eq!(
        token_client.balance(&recipient)
            + token_client.balance(&arbiter)
            + token_client.balance(&collector),
        amount
    );
    assert_eq!(
        client.get_commitment_state(&commitment),
        Some(EscrowStatus::Spent)
    );
}

#[test]
fn test_fee_router_collector_rotation_applies_to_new_payouts_and_old_escrows() {
    let (env, client, admin) = setup();

    let token_id = create_token(&env);
    let owner = Address::generate(&env);
    let collector_v1 = Address::generate(&env);
    let collector_v2 = Address::generate(&env);

    let token_admin = token::StellarAssetClient::new(&env, &token_id);
    let token_client = token::Client::new(&env, &token_id);

    token_admin.mint(&owner, &20_000);

    client.set_fee_config(&admin, &crate::types::FeeConfig { fee_bps: 1_000 });
    client.set_platform_wallet(&admin, &collector_v1);

    // Escrow created before rotation.
    let amount_old: i128 = 1_000;
    let salt_old = Bytes::from_slice(&env, b"fee_router_old_escrow");
    let old_commitment = client.deposit(&token_id, &amount_old, &owner, &salt_old, &0, &None);

    // Rotate collector safely.
    let next_idx = client.rotate_fee_collector(&admin, &collector_v2);
    assert!(next_idx > 0);
    assert_eq!(
        client.get_active_fee_collector(),
        Some(collector_v2.clone())
    );

    // Settling old escrow after rotation should route fee to collector_v2.
    client.withdraw(&token_id, &amount_old, &old_commitment, &owner, &salt_old);

    // New escrow after rotation should also route to collector_v2.
    let amount_new: i128 = 1_000;
    let salt_new = Bytes::from_slice(&env, b"fee_router_new_escrow");
    let new_commitment = client.deposit(&token_id, &amount_new, &owner, &salt_new, &0, &None);
    client.withdraw(&token_id, &amount_new, &new_commitment, &owner, &salt_new);

    // 10% fee on each withdrawal => 100 + 100.
    assert_eq!(token_client.balance(&collector_v1), 0);
    assert_eq!(token_client.balance(&collector_v2), 200);

    // Old and new escrows both settled successfully.
    assert_eq!(
        client.get_commitment_state(&old_commitment),
        Some(EscrowStatus::Spent)
    );
    assert_eq!(
        client.get_commitment_state(&new_commitment),
        Some(EscrowStatus::Spent)
    );
}
