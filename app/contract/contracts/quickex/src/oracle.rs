use crate::{storage, types::OracleFeeConfig};
use soroban_sdk::{Address, Env, Symbol, TryIntoVal, Val};

pub fn get_oracle_fee_config(env: &Env) -> Option<OracleFeeConfig> {
    storage::get_oracle_fee_config(env)
}

pub fn fetch_price(env: &Env, oracle: &Address) -> Option<(i128, u64)> {
    let args = soroban_sdk::vec![env];
    let result = env.try_invoke_contract::<Val, Val>(oracle, &Symbol::new(env, "get_price"), args);

    match result {
        Ok(Ok(value)) => value.try_into_val(env).ok(),
        _ => None,
    }
}
