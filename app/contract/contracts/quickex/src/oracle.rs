use crate::{storage, types::OracleFeeConfig};
use soroban_sdk::{Address, Env};

pub fn get_oracle_fee_config(env: &Env) -> Option<OracleFeeConfig> {
    storage::get_oracle_fee_config(env)
}

pub fn fetch_price(_env: &Env, _oracle: &Address) -> Option<(i128, u64)> {
    // TODO: Implement oracle price fetch once oracle contract is defined
    None
}
