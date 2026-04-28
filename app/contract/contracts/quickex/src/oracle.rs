use crate::{storage, types::OracleFeeConfig};
use soroban_sdk::{contractclient, Address, Env};

#[contractclient]
pub struct PriceOracleClient<'a> {
    env: &'a Env,
    contract_id: &'a Address,
}

impl<'a> PriceOracleClient<'a> {
    pub fn get_price(&self) -> Result<(i128, u64), ()>;
}

pub fn get_oracle_fee_config(env: &Env) -> Option<OracleFeeConfig> {
    storage::get_oracle_fee_config(env)
}

pub fn set_oracle_fee_config(env: &Env, config: &OracleFeeConfig) {
    storage::set_oracle_fee_config(env, config);
}

pub fn fetch_price(env: &Env, oracle: &Address) -> Option<(i128, u64)> {
    let client = PriceOracleClient::new(env, oracle);
    client.get_price().ok()
}
