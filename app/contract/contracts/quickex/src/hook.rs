use crate::{errors::QuickexError, storage, types::HookEventKind};
use soroban_sdk::{Address, BytesN, Env, IntoVal, Symbol, Vec};

pub fn register_hook(env: &Env, hook_contract: Address) -> Result<(), QuickexError> {
    if !storage::is_hook_allowed(env, &hook_contract) {
        return Err(QuickexError::HookNotAllowed);
    }
    let mut hooks = storage::get_registered_hooks(env);
    if hooks.contains(hook_contract.clone()) {
        return Err(QuickexError::HookAlreadyRegistered);
    }

    validate_hook_contract(env, &hook_contract)?;

    hooks.push_back(hook_contract.clone());
    storage::set_registered_hooks(env, &hooks);
    log_hook_event(env, "HookRegistered", &hook_contract, true);
    Ok(())
}

fn validate_hook_contract(env: &Env, hook_contract: &Address) -> Result<(), QuickexError> {
    if *hook_contract == env.current_contract_address() {
        return Err(QuickexError::InvalidAmount);
    }
    Ok(())
}

pub fn unregister_hook(env: &Env, hook_contract: Address) -> Result<(), QuickexError> {
    let hooks = storage::get_registered_hooks(env);
    let mut updated = Vec::new(env);
    let mut found = false;
    for hook in hooks {
        if hook != hook_contract {
            updated.push_back(hook);
        } else {
            found = true;
        }
    }
    if !found {
        return Err(QuickexError::HookNotRegistered);
    }
    storage::set_registered_hooks(env, &updated);
    log_hook_event(env, "HookUnregistered", &hook_contract, true);
    Ok(())
}

pub fn get_registered_hooks(env: &Env) -> Vec<Address> {
    storage::get_registered_hooks(env)
}

pub fn assert_not_reentrant(env: &Env) -> Result<(), QuickexError> {
    if storage::get_reentrancy_guard(env) {
        return Err(QuickexError::ReentrancyDetected);
    }
    Ok(())
}

pub fn invoke_hooks(
    env: &Env,
    event_kind: HookEventKind,
    escrow_id: &BytesN<32>,
    owner: Address,
    token: Address,
    amount: i128,
    fee: i128,
) {
    if storage::get_reentrancy_guard(env) {
        return;
    }

    storage::set_reentrancy_guard(env, &true);
    let hooks = storage::get_registered_hooks(env);
    for hook in hooks {
        let args = soroban_sdk::vec![
            env,
            (event_kind as u32).into_val(env),
            escrow_id.into_val(env),
            owner.clone().into_val(env),
            token.clone().into_val(env),
            amount.into_val(env),
            fee.into_val(env),
        ];

        let start_time = env.ledger().timestamp();
        let result = env.try_invoke_contract::<soroban_sdk::Val, soroban_sdk::Val>(
            &hook,
            &Symbol::new(env, "on_escrow_event"),
            args,
        );
        let end_time = env.ledger().timestamp();
        let execution_time = end_time.saturating_sub(start_time);

        match result {
            Ok(_) => {
                if execution_time > 5 {
                    log_hook_event(env, "HookTimeoutWarning", &hook, false);
                }
            }
            Err(_) => {
                log_hook_event(env, "HookInvocationFailed", &hook, false);
            }
        }
    }
    storage::set_reentrancy_guard(env, &false);
}

fn log_hook_event(env: &Env, event_type: &str, hook_contract: &Address, _is_success: bool) {
    let event_symbol = Symbol::new(env, event_type);
    env.log().info(&event_symbol, &hook_contract);
}
