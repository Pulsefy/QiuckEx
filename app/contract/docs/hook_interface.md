# Hook Interface Documentation

The QuickEx contract supports **hook contracts** that can react to escrow events. Hooks are registered by the admin and invoked during escrow lifecycle operations (create, settle, refund).

## Hook Contract Trait

```rust
pub trait HookContract {
    fn on_escrow_event(
        env: &Env,
        event_kind: u32,            // HookEventKind as a u32
        escrow_id: BytesN<32>,      // Escrow identifier
        owner: Address,            // Owner of the escrow
        token: Address,            // Token used in the escrow
        amount: i128,              // Amount locked in the escrow
        fee: i128,                 // Fee charged for the escrow
    ) -> Result<(), QuickexError>;
}
```

### Requirements
- The function must **not abort** the primary transaction. Errors are swallowed by the core contract to ensure failure isolation.
- Hooks are executed **in FIFO order** of registration.
- Standard Soroban resource limits apply (gas budget, call depth).

## Registration Flow
1. **Admin registers a hook** using `register_hook(env, hook_contract_address)`.
2. The core contract validates the hook is allowed via the allow‑list.
3. Hook address is stored in a vector; later events iterate over this vector.

## Invocation Semantics
- When an escrow event occurs (`Create`, `Settle`, `Refund`), `invoke_hooks` is called.
- The core contract sets a re‑entrancy guard to prevent recursive calls.
- Each hook is invoked via `env.try_invoke_contract` – any error is ignored.
- After all hooks are called, the re‑entrancy guard is cleared.

## Resource Limits
- **Gas:** Each hook call consumes gas like any contract call; the core contract does not enforce a per‑hook limit beyond the overall transaction budget.
- **Call Depth:** Soroban enforces a maximum call depth (default 10). Hooks must stay within this limit.

## Reference Implementation
A minimal reference hook is provided in the `reference_hook` crate. It simply logs the event and returns `Ok(())`.

```rust
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
```

## Failure Isolation Example
A deliberately failing hook (`failing_hook` crate) returns an error. Even when registered, its failure does not abort the escrow transaction.

## Usage
1. Build and deploy the `reference_hook` contract.
2. Register it via `client.register_hook(&admin, &hook_address)`.
3. Perform escrow operations; the hook will be invoked automatically.

---
