#![allow(dead_code)]
#![allow(clippy::result_unit_err)]

use crate::{
    types::{FeeConfig, HookEventKind, OracleFeeConfig},
    QuickexContract, QuickexContractClient,
};
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger},
    token, Address, Bytes, BytesN, Env, Symbol,
};

#[contract]
pub struct HookStubContract;

#[contractimpl]
impl HookStubContract {
    pub fn on_escrow_event(
        env: Env,
        _event_kind: u32,
        _escrow_id: BytesN<32>,
        _owner: Address,
        _token: Address,
        _amount: i128,
        _fee: i128,
    ) -> Result<(), ()> {
        let key = Symbol::short("invocations");
        let mut count: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        count += 1;
        env.storage().persistent().set(&key, &count);
        Ok(())
    }

    pub fn get_invocations(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&Symbol::short("invocations"))
            .unwrap_or(0)
    }
}

#[contract]
pub struct MaliciousHookContract;

#[contractimpl]
impl MaliciousHookContract {
    pub fn init(env: Env, target: Address) {
        env.storage()
            .persistent()
            .set(&Symbol::short("target"), &target);
    }

    pub fn on_escrow_event(
        env: Env,
        event_kind: u32,
        _escrow_id: BytesN<32>,
        _owner: Address,
        _token: Address,
        _amount: i128,
        _fee: i128,
    ) -> Result<(), ()> {
        if event_kind != HookEventKind::Settle as u32 {
            return Ok(());
        }
        let target: Address = env
            .storage()
            .persistent()
            .get(&Symbol::short("target"))
            .unwrap();
        let client = QuickexContractClient::new(&env, &target);
        let random_hook = Address::generate(&env);
        let _ = client.register_hook(&random_hook);
        Err(())
    }
}

#[contract]
pub struct MockOracleContract;

#[contractimpl]
impl MockOracleContract {
    pub fn set_price(env: Env, price_micros: i128, timestamp: u64) {
        env.storage()
            .persistent()
            .set(&Symbol::short("price"), &price_micros);
        env.storage()
            .persistent()
            .set(&Symbol::short("timestamp"), &timestamp);
    }

    pub fn get_price(env: Env) -> Result<(i128, u64), ()> {
        let price: i128 = env
            .storage()
            .persistent()
            .get(&Symbol::short("price"))
            .unwrap_or(0);
        let timestamp: u64 = env
            .storage()
            .persistent()
            .get(&Symbol::short("timestamp"))
            .unwrap_or(0);
        if price <= 0 {
            return Err(());
        }
        Ok((price, timestamp))
    }
}

fn setup<'a>(
    env: &'a Env,
) -> (
    QuickexContractClient<'a>,
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
fn test_hook_callbacks_do_not_block_escrow_flow() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _platform_wallet, owner, _) = setup(&env);

    let hook_contract_id = env.register(HookStubContract, ());
    client.register_hook(&hook_contract_id);

    let token_admin = Address::generate(&env);
    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_id);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_id);
    token_admin_client.mint(&owner, &10000);

    let salt = Bytes::from_array(&env, &[1; 32]);
    let commitment = client.deposit(&token_id, &1000i128, &owner, &salt, &3600, &None);
    client.withdraw(&token_id, &1000i128, &commitment, &owner, &salt);

    let hook_client = HookStubContractClient::new(&env, &hook_contract_id);
    assert_eq!(hook_client.get_invocations(), 2);
    assert_eq!(token_client.balance(&owner), 9999);
}

#[test]
fn test_reentrant_hook_does_not_break_primary_transaction() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _platform_wallet, owner, _) = setup(&env);

    let hook_contract_id = env.register(MaliciousHookContract, ());
    let hook_client = MaliciousHookContractClient::new(&env, &hook_contract_id);
    hook_client.init(&client.address);
    client.register_hook(&hook_contract_id);

    let token_admin = Address::generate(&env);
    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_id);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_id);
    token_admin_client.mint(&owner, &10000);

    let salt = Bytes::from_array(&env, &[2; 32]);
    let commitment = client.deposit(&token_id, &1000i128, &owner, &salt, &3600, &None);
    client.withdraw(&token_id, &1000i128, &commitment, &owner, &salt);

    assert_eq!(token_client.balance(&owner), 9999);
}

#[test]
fn test_oracle_dynamic_fee_and_stale_fallback() {
    let env = Env::default();
    let (client, admin, platform_wallet, owner, _) = setup(&env);
    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_id);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_id);
    token_admin_client.mint(&owner, &10000);

    client.set_platform_wallet(&admin, &platform_wallet);
    client.set_fee_config(&admin, &FeeConfig { fee_bps: 1000 });

    let oracle_id = env.register(MockOracleContract, ());
    let oracle_client = MockOracleContractClient::new(&env, &oracle_id);
    oracle_client.set_price(&1_000_000i128, &1000u64);

    client.set_oracle_fee_config(
        &admin,
        &OracleFeeConfig {
            oracle: oracle_id.clone(),
            usd_fee_micros: 1_000_000,
            stale_threshold_secs: 1000,
        },
    );

    let salt = Bytes::from_array(&env, &[3; 32]);
    let commitment = client.deposit(&token_id, &1000i128, &owner, &salt, &3600, &None);
    client.withdraw(&token_id, &1000i128, &commitment, &owner, &salt);

    assert_eq!(token_client.balance(&owner), 9999);
    assert_eq!(token_client.balance(&platform_wallet), 1);

    // Make oracle data stale and verify fallback to static basis points.
    env.ledger().with_mut(|li| li.timestamp = 3000);
    oracle_client.set_price(&1_000_000i128, &1000u64);

    let salt2 = Bytes::from_array(&env, &[4; 32]);
    let commitment2 = client.deposit(&token_id, &1000i128, &owner, &salt2, &3600, &None);
    client.withdraw(&token_id, &1000i128, &commitment2, &owner, &salt2);

    assert_eq!(token_client.balance(&owner), 9999 + 900);
    assert_eq!(token_client.balance(&platform_wallet), 1 + 100);
}
