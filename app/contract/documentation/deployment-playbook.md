# QuickEx Soroban Deployment Playbook

This playbook defines the repeatable deployment process for QuickEx Soroban contracts.

The goals are:

- deterministic testnet deployments for new contributors,
- auditable environment tracking,
- gated mainnet promotion,
- idempotent deploy behavior, and
- fast recovery if a deployment must be paused or upgraded.

## 1. Deployment targets

### Testnet

- Default deployment target.
- Safe place to validate the release artifact, registry updates, and smoke tests.
- Every new release should be deployed here first.

### Mainnet

- Gated target.
- Requires completed testnet validation, governance sign-off, and registry review.
- Mainnet deploys should reuse the exact artifact and process that succeeded on testnet.

## 2. Standard Soroban CLI setup

Use one named identity per environment and one network profile per chain. The exact Soroban CLI subcommand names can vary by CLI release, so treat the commands below as the expected operator flow rather than a hard binary contract.

Recommended operator shell variables:

```bash
export QUICKEX_TESTNET_RPC_URL="https://soroban-testnet.stellar.org"
export QUICKEX_TESTNET_PASSPHRASE="Test SDF Network ; September 2015"
export QUICKEX_TESTNET_IDENTITY="quickex-testnet"

export QUICKEX_MAINNET_RPC_URL="https://mainnet.stellar.org"
export QUICKEX_MAINNET_PASSPHRASE="Public Global Stellar Network ; September 2015"
export QUICKEX_MAINNET_IDENTITY="quickex-mainnet"
```

Suggested network bootstrap flow:

```bash
soroban config network add testnet \
  --rpc-url "$QUICKEX_TESTNET_RPC_URL" \
  --network-passphrase "$QUICKEX_TESTNET_PASSPHRASE"

soroban config network add mainnet \
  --rpc-url "$QUICKEX_MAINNET_RPC_URL" \
  --network-passphrase "$QUICKEX_MAINNET_PASSPHRASE"
```

Suggested identity bootstrap flow:

```bash
soroban config identity generate "$QUICKEX_TESTNET_IDENTITY"
soroban config identity generate "$QUICKEX_MAINNET_IDENTITY"
```

Use the identity names consistently in deploy scripts, release notes, and the environment registry.

## 3. Environment registry

The environment registry is the source of truth for deployed contract state.

Minimum fields per environment:

- `network`
- `rpc_url`
- `network_passphrase`
- `identity`
- `contract_id`
- `wasm_hash`
- `admin_addresses`
- `init_params`
- `deployed_at`
- `deployed_by`
- `notes`

The live registry is [environment-registry.toml](environment-registry.toml).
The schema example is [environment-registry.example.toml](environment-registry.example.toml).

## 4. Idempotent deployment flow

The deploy process must be safe to re-run.

### Decision tree

1. Read the registry entry for the target network.
2. Query the deployed contract with `get_deployment_metadata`.
3. Compare the recorded `contract_id` and `wasm_hash` against the registry.
4. If both match, skip redeploy and only run validation.
5. If the registry has no entry, deploy and write a new registry record.
6. If the contract exists but the hash differs, treat it as an upgrade path.
7. On mainnet, do not redeploy or upgrade without explicit governance approval.

### Testnet idempotent flow

```bash
cargo build --target wasm32v1-none --release

# Deploy only when the registry entry is missing or the release hash changed.
stellar contract deploy \
  --wasm target/wasm32v1-none/release/quickex.wasm \
  --source "$QUICKEX_TESTNET_IDENTITY" \
  --network testnet

stellar contract invoke \
  --id <CONTRACT_ID> \
  --source "$QUICKEX_TESTNET_IDENTITY" \
  --network testnet \
  -- \
  get_deployment_metadata
```

### Validation rules

- If `contract_id` already exists and metadata matches, the deploy step is a no-op.
- If `wasm_hash` matches but the environment registry is missing, write the registry record before merging.
- If metadata does not match the registry, stop and investigate before proceeding.

## 5. Key management rules

### Testnet

- A single operator identity is acceptable for testnet.
- The identity should still be recorded in the registry.
- Do not reuse personal accounts as the long-term registry identity.

### Mainnet

- No single hot key for operational control.
- Prefer a multi-sig or role-split governance model where admin, deployer, and operator are separate.
- Store every production signer in the registry or an approved secret store reference.
- Document the rotation plan before mainnet promotion.

## 6. Rollback and mitigation

Use mitigation before rollback whenever possible.

### Primary controls

- `set_paused` for global pause.
- `set_pause_flags` for granular feature pauses.
- Emergency mode as the last-resort immutable stop.
- Upgrade path for code fixes when the issue is not a state corruption problem.

### Operational response order

1. Pause the affected flow.
2. Confirm the registry entry and latest deployed metadata.
3. Check monitoring hooks and event delivery.
4. If the issue is code-level and reversible, prepare an upgrade.
5. If the issue is state-level or safety-critical, leave the contract paused and escalate.

### Monitoring hooks

Track at least:

- deployment success or failure,
- `health_check` responses,
- `get_deployment_metadata` output,
- pause and unpause events,
- contract upgrade events,
- event schema version mismatches.

## 7. Testnet release flow

1. Build the release WASM.
2. Deploy to testnet with the testnet identity.
3. Initialize the contract if the release requires init params.
4. Record the resulting contract ID and wasm hash in the registry.
5. Verify metadata with `get_deployment_metadata`.
6. Run `health_check`.
7. Run one event-emitting action and confirm the event schema matches [events-schema.md](../docs/events-schema.md).
8. Update [environment-registry.toml](environment-registry.toml) and the PR with the deployment result.

## 8. Mainnet release gate

Mainnet requires the following before execution:

- testnet deployment completed and recorded,
- deployment checklist complete,
- governance approval captured,
- registry entry reviewed,
- monitoring hooks enabled,
- pause / emergency access documented.

Mainnet uses the same artifact and validation steps as testnet, but with the mainnet identity and network.

## 9. Contract deployment record

For each environment, record the deployed QuickEx contract address and release details in [environment-registry.toml](environment-registry.toml).

Minimum contract record:

- contract ID
- wasm hash
- admin address(es)
- init params
- deployment timestamp
- operator identity
