use crate::{errors::QuickexError, storage, types::HookEventKind};
use soroban_sdk::{contractclient, Address, BytesN, Env, Vec};

#[contractclient]
pub struct HookClient<'a> {
    env: &'a Env,
    contract_id: &'a Address,
}

impl<'a> HookClient<'a> {
    pub fn on_escrow_event(
        &self,
        event_kind: u32,
        escrow_id: BytesN<32>,
        owner: Address,
        token: Address,
        amount: i128,
        fee: i128,
    ) -> Result<(), ()>;
}

pub fn register_hook(env: &Env, hook_contract: Address) -> Result<(), QuickexError> {
    let mut hooks = storage::get_registered_hooks(env);
    if hooks.contains(hook_contract.clone()) {
        return Err(QuickexError::HookAlreadyRegistered);
    }
    hooks.push_back(hook_contract);
    storage::set_registered_hooks(env, &hooks);
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

    storage::set_reentrancy_guard(env, true);
    let hooks = storage::get_registered_hooks(env);
    for hook in hooks {
        let hook_client = HookClient::new(env, &hook);
        let _ = hook_client.on_escrow_event(
            event_kind as u32,
            escrow_id.clone(),
            owner.clone(),
            token.clone(),
            amount,
            fee,
        );
    }
    storage::set_reentrancy_guard(env, false);
}
