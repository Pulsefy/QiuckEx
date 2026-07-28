use crate::{storage, types::OracleFeeConfig};
use soroban_sdk::{Address, Env, Error, Symbol};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleAdapterKind {
    Testnet,
}

pub trait OraclePriceAdapter {
    fn fetch_price(&self, env: &Env, oracle: &Address) -> Option<(i128, u64)>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestnetOracleAdapter;

impl OraclePriceAdapter for TestnetOracleAdapter {
    fn fetch_price(&self, env: &Env, oracle: &Address) -> Option<(i128, u64)> {
        let args = soroban_sdk::vec![env];
        match env.try_invoke_contract::<(i128, u64), Error>(oracle, &Symbol::new(env, "get_price"), args) {
            Ok(Ok((price_micros, timestamp))) => {
                if price_micros <= 0 || timestamp == 0 {
                    None
                } else {
                    Some((price_micros, timestamp))
                }
            }
            Ok(Err(_)) | Err(_) => None,
        }
    }
}

pub fn get_oracle_fee_config(env: &Env) -> Option<OracleFeeConfig> {
    storage::get_oracle_fee_config(env)
}

pub fn fetch_price(env: &Env, oracle: &Address) -> Option<(i128, u64)> {
    fetch_price_with_provider(env, oracle, OracleAdapterKind::Testnet)
}

pub fn fetch_price_with_provider(
    env: &Env,
    oracle: &Address,
    provider: OracleAdapterKind,
) -> Option<(i128, u64)> {
    match provider {
        OracleAdapterKind::Testnet => TestnetOracleAdapter.fetch_price(env, oracle),
    }
}

#[cfg(test)]
mod tests {
    use super::{fetch_price, fetch_price_with_provider, OracleAdapterKind};
    use soroban_sdk::{contract, contractimpl, Env, Error};

    #[contract]
    struct MockOracleContract;

    #[contractimpl]
    impl MockOracleContract {
        pub fn set_price(env: Env, price_micros: i128, timestamp: u64) {
            env.storage()
                .persistent()
                .set(&soroban_sdk::Symbol::new(&env, "price"), &price_micros);
            env.storage()
                .persistent()
                .set(&soroban_sdk::Symbol::new(&env, "timestamp"), &timestamp);
        }

        pub fn get_price(env: Env) -> Result<(i128, u64), Error> {
            let price: i128 = env
                .storage()
                .persistent()
                .get(&soroban_sdk::Symbol::new(&env, "price"))
                .unwrap_or(0);
            let timestamp: u64 = env
                .storage()
                .persistent()
                .get(&soroban_sdk::Symbol::new(&env, "timestamp"))
                .unwrap_or(0);
            if price <= 0 || timestamp == 0 {
                return Err(Error::from_contract_error(1));
            }
            Ok((price, timestamp))
        }
    }

    #[test]
    fn fetch_price_returns_valid_payload_from_real_adapter() {
        let env = Env::default();
        let oracle_id = env.register(MockOracleContract, ());
        let oracle_client = MockOracleContractClient::new(&env, &oracle_id);
        oracle_client.set_price(&1_000_000i128, &1_000u64);

        let fetched = fetch_price_with_provider(&env, &oracle_id, OracleAdapterKind::Testnet);

        assert_eq!(fetched, Some((1_000_000i128, 1_000u64)));
    }

    #[test]
    fn fetch_price_rejects_invalid_payload() {
        let env = Env::default();
        let oracle_id = env.register(MockOracleContract, ());
        let oracle_client = MockOracleContractClient::new(&env, &oracle_id);
        oracle_client.set_price(&0i128, &1_000u64);

        let fetched = fetch_price(&env, &oracle_id);

        assert!(fetched.is_none());
    }
}
