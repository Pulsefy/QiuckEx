use soroban_sdk::{contractimpl, contracttype, Address, BytesN, Env};
use quickex::errors::QuickexError;
use quickex::types::HookEventKind;
use quickex::hook_trait::HookContract;

/// Hook that intentionally fails by returning an error.
pub struct FailingHook;

impl HookContract for FailingHook {
    fn on_escrow_event(
        _env: &Env,
        _event_kind: u32,
        _escrow_id: BytesN<32>,
        _owner: Address,
        _token: Address,
        _amount: i128,
        _fee: i128,
    ) -> Result<(), QuickexError> {
        Err(QuickexError::HookNotAllowed)
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
        FailingHook::on_escrow_event(&env, event_kind, escrow_id, owner, token, amount, fee)
    }
}
