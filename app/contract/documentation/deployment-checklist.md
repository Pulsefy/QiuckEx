# QuickEx Deployment Checklist

This checklist is the release gate for any QuickEx deployment change. Use it for testnet validation first, then repeat the exact validated steps for mainnet.

## 1. Required checks before deployment

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test`
- [ ] `cargo test bench_ -- --nocapture`
- [ ] `cargo test upgrade_harness_ -- --nocapture`
- [ ] `cargo test test_event_schema_catalog_locks_canonical_topics_and_payloads`

If the PR touches an event payload, also run the relevant snapshot test(s) in [contracts/quickex/src/test.rs](../contracts/quickex/src/test.rs) and confirm the payload keys remain locked.

## 2. Governance requirements

- [ ] Threshold keys are set and the signer set is documented.
- [ ] Pause policy is configured before deployment.
- [ ] The admin key / deploy source used for the network is explicit in the PR.
- [ ] The rollback or pause path is documented before mainnet promotion.

## 3. Testnet deployment gate

1. Build the release WASM artifact.
2. Deploy to testnet with the test source key.
3. Initialize the contract if the release requires it.
4. Verify the deployment metadata view.
5. Run a health check.
6. Run an event emission smoke test and confirm the emitted event includes `schema_version` and the expected topic shape.

Suggested validation commands:

```bash
cargo build --target wasm32-unknown-unknown --release
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/quickex.wasm \
  --source test \
  --network testnet

soroban contract invoke \
  --id <CONTRACT_ID> \
  --source test \
  --network testnet \
  -- \
  health_check

soroban contract invoke \
  --id <CONTRACT_ID> \
  --source test \
  --network testnet \
  -- \
  get_deployment_metadata
```

For the smoke test, invoke one known event-emitting action on testnet, then confirm the event payload matches [docs/events-schema.md](../docs/events-schema.md).

## 4. Mainnet deployment gate

Mainnet deployment is only allowed after the exact testnet command sequence above has been completed and recorded.

1. Reuse the same release WASM artifact that passed testnet validation.
2. Reuse the same operator checklist and deployment order.
3. Replace the network and source key with the mainnet equivalents.
4. Re-run metadata and health validation immediately after deployment.
5. Re-run the event emission smoke test and confirm the schema is unchanged.

Suggested command shape:

```bash
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/quickex.wasm \
  --source main \
  --network mainnet
```

## 5. What reviewers should confirm

- [ ] The PR links the exact deployment checklist result.
- [ ] The testnet validation output is attached or summarized.
- [ ] The mainnet steps are explicit and repeatable.
- [ ] The post-deploy validation confirms metadata, health, and event emission.
- [ ] The PR template checklist is completed for any release-related change.
