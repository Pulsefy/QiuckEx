use soroban_sdk::{Address, BytesN, Env};
use crate::errors::QuickexError;
use crate::types::HookEventKind;

/// Trait that any hook contract must implement.
///
/// The core contract invokes `on_escrow_event` on each registered hook.
/// Implementors should ensure that failing logic does **not** abort the primary
/// transaction – the core contract swallows any error returned from this call.
///
/// * `event_kind` – numeric representation of the `HookEventKind` enum.
/// * `escrow_id` – identifier of the escrow.
/// * `owner`, `token` – participants of the escrow.
/// * `amount`, `fee` – monetary values involved.
///
/// Returns `Result<(), QuickexError>` where `Ok(())` indicates successful
/// processing. Errors are logged by the core contract and ignored to maintain
/// failure isolation.
pub trait HookContract {
    fn on_escrow_event(
        env: &Env,
        event_kind: u32,
        escrow_id: BytesN<32>,
        owner: Address,
        token: Address,
        amount: i128,
        fee: i128,
    ) -> Result<(), QuickexError>;
}
