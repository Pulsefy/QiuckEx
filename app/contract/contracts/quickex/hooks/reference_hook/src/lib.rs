use soroban_sdk::{contractimpl, contracttype, Address, BytesN, Env};
use quickex::errors::QuickexError;
use quickex::types::HookEventKind;
use quickex::hook_trait::HookContract;

/// Simple reference hook that just logs the event.
pub struct ReferenceHook;

impl HookContract for ReferenceHook {
    fn on_escrow_event(
        env: &Env,
        event_kind: u32,
        escrow_id: BytesN<32>,
        owner: Address,
        token: Address,
        amount: i128,
        fee: i128,
    ) -> Result<(), QuickexError> {
        env.log(&format!(
            "ReferenceHook invoked: kind={{}}, escrow={{:?}}, owner={{}}, token={{}}, amount={{}}, fee={{}}",
            event_kind, escrow_id, owner, token, amount, fee,
        ));
        Ok(())
    }
}

#[contracttype]
pub struct HookContractImpl;

#[contractimpl]
impl HookContractImpl {
    pub fn on_escrow_event(
        env: Env,
        event_kind: u32,
        escrow_id: BytesN<32>,
        owner: Address,
        token: Address,
        amount: i128,
        fee: i128,
    ) -> Result<(), QuickexError> {
        ReferenceHook::on_escrow_event(&env, event_kind, escrow_id, owner, token, amount, fee)
    }
}
