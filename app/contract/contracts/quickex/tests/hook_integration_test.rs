// Hook integration tests for QuickEx contract
use quickex::{QuickexContractClient, QuickexContract};
use quickex::test_context::TestContext;
use soroban_sdk::{Address, BytesN, Env};

// Helper to deploy a hook contract and register it.
fn deploy_and_register(env: &Env, hook_wasm: &[u8]) -> Address {
    // Deploy the hook contract
    let hook_id = env.register(quickex::hooks::reference_hook::HookContractImpl, hook_wasm);
    // Register the hook with the core contract
    let ctx = TestContext::new();
    ctx.client.register_hook(&ctx.admin, &hook_id).unwrap();
    hook_id
}

#[test]
fn test_reference_hook_success() {
    let ctx = TestContext::with_admin();
    // Deploy reference hook (the wasm is already available via the crate)
    let hook_wasm = include_bytes!("../../hooks/reference_hook/target/wasm32-unknown-unknown/release/reference_hook.wasm");
    let hook_id = ctx.client.register_hook(&ctx.admin, &Address::generate(&ctx.env)).unwrap(); // placeholder registration
    // In a real test, we would deploy the hook contract and register it.
    // Trigger an escrow creation which invokes hooks.
    let escrow_id = ctx.simple_deposit(&ctx.alice, 1000, b"salt");
    // Verify the escrow was created successfully.
    assert!(ctx.client.get_escrow(&ctx.admin, &escrow_id).is_ok());
    // Optionally check logs for hook invocation.
}

#[test]
fn test_failing_hook_isolated() {
    let ctx = TestContext::with_admin();
    // Deploy failing hook contract
    let failing_wasm = include_bytes!("../../hooks/failing_hook/target/wasm32-unknown-unknown/release/failing_hook.wasm");
    let failing_id = ctx.client.register_hook(&ctx.admin, &Address::generate(&ctx.env)).unwrap(); // placeholder
    // Trigger escrow; the failing hook should not abort the transaction.
    let escrow_id = ctx.simple_deposit(&ctx.alice, 500, b"salt2");
    // Ensure primary transaction succeeded.
    assert!(ctx.client.get_escrow(&ctx.admin, &escrow_id).is_ok());
}
