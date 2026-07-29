# Requirements Document

## Introduction

This feature replaces the single-admin governance model in the QuickEx Soroban smart contract with a threshold-based multisig governance system. Currently, one address can unilaterally execute all privileged actions (pause, upgrades, fee configuration, platform wallet, role management). The goal is to require a configurable M-of-N set of signers to collectively approve proposals before any privileged action executes on-chain.

The system must be suitable for testnet deployment and designed to support future mainnet operations. It builds on existing replay-protection primitives (`NonceAlreadyUsed`, `SignatureExpired`) and the multi-sig arbiter threshold pattern already present in `EscrowEntry`.

## Glossary

- **Governance_Module**: The on-chain component responsible for managing proposals, collecting approvals, enforcing thresholds, and executing privileged actions.
- **Proposal**: A pending governance action stored on-chain, identified by a unique `proposal_id` (BytesN<32>), containing the action type, parameters, expiry timestamp, and approval state.
- **Signer**: An address that is a member of the governance signer set and is authorized to approve proposals.
- **Signer_Set**: The ordered collection of `Address` values that constitute the current governance council. Managed on-chain under a dedicated storage key.
- **Threshold**: The minimum number of distinct Signer approvals required for a Proposal to become executable. Stored as `u32`. Must satisfy `1 ≤ threshold ≤ |Signer_Set|`.
- **Approval**: A record that a specific Signer has voted to execute a specific Proposal, stored on-chain to prevent double-voting.
- **Execution**: The act of applying a Proposal's privileged action to contract state after the Threshold is met.
- **Cancellation**: The act of permanently invalidating a Proposal before it is executed, callable by any Signer.
- **ProposalAction**: A tagged union (enum) encoding the privileged action and its parameters. Variants: `SetPaused`, `SetPauseFlags`, `UpgradeContract`, `SetFeeConfig`, `SetPerAssetFee`, `SetPlatformWallet`, `SetAdmin`, `GrantRole`, `RevokeRole`, `UpdateSignerSet`.
- **Nonce**: A per-signer monotonically-consumed `u64` value used for replay protection, reusing the existing `nonce::verify_and_consume` mechanism.
- **Expiry**: A ledger timestamp (`u64`) embedded in a Proposal beyond which the Proposal cannot be approved or executed.
- **proposal_id**: A 32-byte deterministic identifier derived as `SHA256(action_tag || encoded_params || proposer || nonce || valid_until)`.
- **TOPIC_GOVERNANCE**: The event topic domain string for all governance lifecycle events.
- **Admin**: The existing `Role::Admin` role; during the migration period the legacy admin address is seeded as the sole Signer with threshold 1.

## Requirements

---

### Requirement 1: Governance Initialization

**User Story:** As a contract deployer, I want to initialize the governance signer set and threshold at contract setup time, so that privileged actions are protected from the first deployment.

#### Acceptance Criteria

1. WHEN `initialize` is called, THE Governance_Module SHALL accept an initial `signers: Vec<Address>` and `threshold: u32` parameter alongside the existing `admin` parameter.
2. WHEN `initialize` is called and the contract has already been initialized, THEN THE Governance_Module SHALL return `AlreadyInitialized` (error 201) without modifying any state.
3. WHEN `initialize` is called with an empty `signers` vector, THEN THE Governance_Module SHALL return `InvalidSignerSet` (error code 503) before evaluating the threshold.
4. WHEN `initialize` is called with a `signers` vector containing more than 10 addresses, THEN THE Governance_Module SHALL return `InvalidSignerSet` (error code 503).
5. WHEN `initialize` is called with `threshold == 0` or `threshold > signers.len()`, THEN THE Governance_Module SHALL return `InvalidThreshold` (error code 502).
6. WHEN `initialize` is called with duplicate addresses in `signers`, THEN THE Governance_Module SHALL return `DuplicateSigner` (error code 504).
7. WHEN `initialize` is called with a zero address (`Address::zero()`) in `signers`, THEN THE Governance_Module SHALL return `InvalidSignerSet` (error code 503).
8. WHEN `initialize` completes successfully, THE Governance_Module SHALL store the Signer_Set and Threshold in persistent storage.
9. WHEN `initialize` completes successfully, THE Governance_Module SHALL seed the existing `Admin` storage key with the address at index 0 of the `signers` vector for backwards compatibility with the legacy admin check.

---

### Requirement 2: Proposal Creation

**User Story:** As a Signer, I want to create a governance proposal for a privileged action, so that other signers can review and approve it before it executes.

#### Acceptance Criteria

1. WHEN a Signer calls `create_proposal` with a `ProposalAction`, `nonce`, and `valid_until`, THE Governance_Module SHALL verify the caller is a member of the Signer_Set — IF the caller is not a member, THEN THE Governance_Module SHALL return `NotASigner` (error code 505) without modifying any state.
2. IF the caller is a Signer AND `env.ledger().timestamp() >= valid_until`, THEN THE Governance_Module SHALL return `SignatureExpired` (error 501) without modifying any state.
3. IF the caller is a Signer AND `valid_until - env.ledger().timestamp() > 2,592,000` (30 days), THEN THE Governance_Module SHALL return `ExpiryTooFar` (error code 511) without modifying any state.
4. IF the caller is a Signer AND the `(caller, nonce)` pair has already been consumed, THEN THE Governance_Module SHALL return `NonceAlreadyUsed` (error 500) without modifying any state.
5. IF the caller is a Signer AND the `ProposalAction` variant is unrecognized or malformed, THEN THE Governance_Module SHALL return `InvalidProposalState` (error code 508) without modifying any state.
6. WHEN `create_proposal` passes all validation, THE Governance_Module SHALL derive `proposal_id` as `SHA256(action_tag || encoded_params || proposer || nonce || valid_until)`.
7. IF the derived `proposal_id` already exists in storage, THEN THE Governance_Module SHALL return `ProposalAlreadyExists` (error code 506) without modifying any state.
8. WHEN `create_proposal` passes all validation including a unique `proposal_id`, THE Governance_Module SHALL atomically: store the Proposal in persistent storage, record the proposer's address as the first Approval, consume the `(caller, nonce)` pair via `nonce::verify_and_consume`, and emit a `ProposalCreated` event — all four operations SHALL succeed or none SHALL take effect.
9. WHEN `create_proposal` emits `ProposalCreated`, the event's `expires_at` field SHALL equal the `valid_until` parameter passed by the caller.

---

### Requirement 3: Approval Collection

**User Story:** As a Signer, I want to approve an existing proposal, so that the proposal can accumulate enough votes to reach the execution threshold.

#### Acceptance Criteria

1. WHEN a Signer calls `approve_proposal` with a `proposal_id`, THE Governance_Module SHALL verify the caller is a member of the Signer_Set.
2. IF the caller is not a member of the Signer_Set, THEN THE Governance_Module SHALL return `NotASigner` (error 505) without modifying any Proposal state.
3. IF the caller is a Signer AND the Proposal does not exist, THEN THE Governance_Module SHALL return `ProposalNotFound` (error code 507) without modifying any state.
4. IF the caller is a Signer AND the Proposal exists AND `env.ledger().timestamp() >= proposal.expires_at`, THEN THE Governance_Module SHALL return `SignatureExpired` (error 501) without modifying any Proposal state.
5. IF the caller is a Signer AND the Proposal exists AND is not expired AND the Proposal is not in `Pending` status, THEN THE Governance_Module SHALL return `InvalidProposalState` (error code 508) without modifying any Proposal state.
6. IF the caller is a Signer AND the Proposal exists AND is not expired AND is `Pending` AND the Signer has already approved the Proposal, THEN THE Governance_Module SHALL return `AlreadyApproved` (error code 509) without modifying any Proposal state.
7. WHEN `approve_proposal` passes all validation (checks 1–6), THE Governance_Module SHALL add the caller's address to the Proposal's approver set, increment the approval count by 1, and emit a `ProposalApproved` event with `proposal_id`, `approver`, the post-approval `approval_count`, and `threshold`. Validation SHALL be evaluated in the order: signer membership → proposal existence → expiry → status → duplicate approval.
8. WHEN the post-approval `approval_count` equals or exceeds the Threshold, THE Governance_Module SHALL transition the Proposal status from `Pending` to `Executable`.

---

### Requirement 4: Proposal Execution

**User Story:** As any caller, I want to execute a proposal that has reached the approval threshold, so that the approved privileged action takes effect on-chain.

#### Acceptance Criteria

1. WHEN `execute_proposal` is called with a `proposal_id`, THE Governance_Module SHALL evaluate checks in this order: proposal existence → expiry → status → approval count.
2. IF the Proposal does not exist, THEN THE Governance_Module SHALL return `ProposalNotFound` (error 507) without modifying any state.
3. IF the Proposal exists AND `env.ledger().timestamp() >= proposal.expires_at`, THEN THE Governance_Module SHALL return `SignatureExpired` (error 501) without modifying any state.
4. IF the Proposal exists AND is not expired AND the Proposal is not in `Pending` or `Executable` status, THEN THE Governance_Module SHALL return `InvalidProposalState` (error 508) without modifying any state.
5. IF the Proposal exists AND is not expired AND has valid status AND the approval count is less than the Threshold, THEN THE Governance_Module SHALL return `InsufficientApprovals` (error code 510) without modifying any state.
6. WHEN `execute_proposal` passes all validation, THE Governance_Module SHALL apply the `ProposalAction` to contract state atomically — IF the action application fails for any reason, THEN no state SHALL be mutated and the Proposal SHALL remain in its current status.
7. WHEN `execute_proposal` passes all validation and the action is applied successfully, THE Governance_Module SHALL mark the Proposal status as `Executed` in storage and emit a `ProposalExecuted` event with `proposal_id`, `action_tag`, and `approval_count`.
8. WHEN a `ProposalAction::UpdateSignerSet` is executed, THE Governance_Module SHALL first validate that the new threshold satisfies `1 ≤ new_threshold ≤ new_signers.len()` — IF this validation fails, THEN THE Governance_Module SHALL return `InvalidThreshold` (error 502) without modifying the Signer_Set or Threshold.
9. WHEN a `ProposalAction::UpdateSignerSet` passes threshold validation, THE Governance_Module SHALL atomically replace the Signer_Set and Threshold in storage.

---

### Requirement 5: Proposal Cancellation

**User Story:** As a Signer, I want to cancel a pending proposal, so that proposals that are no longer desired cannot be executed.

#### Acceptance Criteria

1. WHEN a Signer calls `cancel_proposal` with a `proposal_id`, THE Governance_Module SHALL verify the caller is a member of the Signer_Set.
2. IF the caller is not a member of the Signer_Set, THEN THE Governance_Module SHALL return `NotASigner` (error 505) without modifying any state.
3. WHEN `cancel_proposal` is called by a valid Signer and the Proposal does not exist, THEN THE Governance_Module SHALL return `ProposalNotFound` (error 507) without modifying any state.
4. WHEN `cancel_proposal` is called by a valid Signer and the Proposal exists and is not in `Pending` status, THEN THE Governance_Module SHALL return `InvalidProposalState` (error 508) without modifying any state.
5. WHEN `cancel_proposal` passes all validation (Signer_Set membership, Proposal existence, Pending status), THE Governance_Module SHALL mark the Proposal status as `Cancelled` in storage.
6. WHEN `cancel_proposal` passes all validation, THE Governance_Module SHALL emit a `ProposalCancelled` event with `proposal_id` and `cancelled_by` set to the caller's Signer address.

---

### Requirement 6: Replay and Expiry Protection

**User Story:** As a contract operator, I want all governance actions to be protected against replay attacks and stale submissions, so that the governance system cannot be exploited through replayed or expired messages.

#### Acceptance Criteria

1. WHEN `create_proposal` is called, THE Governance_Module SHALL invoke `nonce::verify_and_consume` to enforce per-signer nonce uniqueness — IF the nonce has already been consumed, THE Governance_Module SHALL return `NonceAlreadyUsed` (error 500) without modifying any proposal state.
2. IF a Proposal's `expires_at` timestamp has been reached (i.e., `env.ledger().timestamp() >= expires_at` using the current block timestamp), THEN THE Governance_Module SHALL reject any `approve_proposal` or `execute_proposal` call on that Proposal with `SignatureExpired` (error 501).
3. THE Governance_Module SHALL store consumed nonces in persistent storage with a 6-month (15,552,000 seconds) TTL.
4. IF `create_proposal` is called and `valid_until - env.ledger().timestamp() > 2,592,000` (30 days, using the current block timestamp), THEN THE Governance_Module SHALL return `ExpiryTooFar` (error code 511) without modifying any state.
5. IF a `(signer, nonce)` pair has been consumed by a prior `create_proposal` call, THEN any subsequent `create_proposal` call using the same `(signer, nonce)` pair SHALL return `NonceAlreadyUsed` (error 500), regardless of the `ProposalAction` type.

---

### Requirement 7: Governance Events

**User Story:** As an indexer or auditor, I want all governance lifecycle transitions to emit structured on-chain events, so that the complete governance history is available for audit trails.

#### Acceptance Criteria

1. WHEN `create_proposal` succeeds, THE Governance_Module SHALL emit `ProposalCreated` under `TOPIC_GOVERNANCE` with topics `[TOPIC_GOVERNANCE, "ProposalCreated", proposal_id, proposer]` and data `{schema_version, action_tag, expires_at, timestamp}`.
2. WHEN `approve_proposal` succeeds, THE Governance_Module SHALL emit `ProposalApproved` under `TOPIC_GOVERNANCE` with topics `[TOPIC_GOVERNANCE, "ProposalApproved", proposal_id, approver]` and data `{schema_version, approval_count, threshold, timestamp}`.
3. WHEN `execute_proposal` succeeds, THE Governance_Module SHALL emit `ProposalExecuted` under `TOPIC_GOVERNANCE` with topics `[TOPIC_GOVERNANCE, "ProposalExecuted", proposal_id]` and data `{schema_version, action_tag, approval_count, timestamp}`.
4. WHEN `cancel_proposal` succeeds, THE Governance_Module SHALL emit `ProposalCancelled` under `TOPIC_GOVERNANCE` with topics `[TOPIC_GOVERNANCE, "ProposalCancelled", proposal_id, cancelled_by]` and data `{schema_version, timestamp}`.
5. WHEN `execute_proposal` succeeds with a `ProposalAction::UpdateSignerSet` action, THE Governance_Module SHALL emit `SignerSetUpdated` under `TOPIC_GOVERNANCE` with topics `[TOPIC_GOVERNANCE, "SignerSetUpdated"]` and data `{schema_version, new_threshold, signer_count, timestamp}` — this event SHALL be emitted after `ProposalExecuted` in the same transaction.
6. EVERY governance event payload SHALL include `schema_version: u32` set to `EVENT_SCHEMA_VERSION` (value: `1`) and a `timestamp: u64` set to `env.ledger().timestamp()`, consistent with the existing event schema.
7. WHEN any governance entrypoint (`create_proposal`, `approve_proposal`, `execute_proposal`, `cancel_proposal`) returns an error, THE Governance_Module SHALL NOT emit any governance event for that call.

---

### Requirement 8: Privileged Action Coverage

**User Story:** As a security auditor, I want every previously single-admin privileged action to be gated behind the governance threshold, so that no single address can unilaterally alter critical contract state.

#### Acceptance Criteria

1. THE Governance_Module SHALL gate `set_paused` / `set_pause_flags` behind a `ProposalAction::SetPaused` / `ProposalAction::SetPauseFlags` proposal that must reach the Threshold before execution.
2. THE Governance_Module SHALL gate contract WASM upgrades behind a `ProposalAction::UpgradeContract` proposal that must reach the Threshold before execution.
3. THE Governance_Module SHALL gate `set_fee_config` behind a `ProposalAction::SetFeeConfig` proposal that must reach the Threshold before execution.
4. THE Governance_Module SHALL gate `set_per_asset_fee` behind a `ProposalAction::SetPerAssetFee` proposal that must reach the Threshold before execution.
5. THE Governance_Module SHALL gate `set_platform_wallet` behind a `ProposalAction::SetPlatformWallet` proposal that must reach the Threshold before execution.
6. THE Governance_Module SHALL gate `set_admin` behind a `ProposalAction::SetAdmin` proposal that must reach the Threshold before execution.
7. THE Governance_Module SHALL gate `grant_role` and `revoke_role` behind `ProposalAction::GrantRole` and `ProposalAction::RevokeRole` proposals that must reach the Threshold before execution.
8. WHEN any of the above direct admin entrypoints (`set_paused`, `upgrade`, `set_fee_config`, `set_per_asset_fee`, `set_platform_wallet`, `set_admin`, `grant_role`, `revoke_role`) are called directly without going through the governance execution path, THEN THE Governance_Module SHALL return `Unauthorized` (error 200).

---

### Requirement 9: Signer Set Query

**User Story:** As an off-chain client or monitoring tool, I want to query the current signer set and threshold, so that I can construct valid proposals and verify governance state.

#### Acceptance Criteria

1. THE Governance_Module SHALL expose a `get_signer_set` read-only entrypoint that returns the current `Vec<Address>` of signers.
2. THE Governance_Module SHALL expose a `get_threshold` read-only entrypoint that returns the current `u32` threshold.
3. THE Governance_Module SHALL expose a `get_proposal` read-only entrypoint that returns the full Proposal struct for a given `proposal_id`, or `None` if not found.
4. THE Governance_Module SHALL expose an `is_signer` read-only entrypoint that returns `true` if a given `Address` is a member of the current Signer_Set.

---

### Requirement 10: Proposal Storage and TTL

**User Story:** As a contract operator, I want proposal data to persist long enough for signers to review and approve, but not indefinitely, so that storage costs remain bounded.

#### Acceptance Criteria

1. THE Governance_Module SHALL store each Proposal in persistent storage under a `DataKey::Proposal(proposal_id)` key.
2. WHEN a Proposal is created, THE Governance_Module SHALL set its storage TTL to at least 30 days (2,592,000 ledger-seconds equivalent) using the existing `extend_ttl` pattern.
3. WHEN a Proposal transitions to `Executed` or `Cancelled` status, THE Governance_Module SHALL set its storage TTL to exactly 7 days (604,800 ledger-seconds equivalent, no deviation permitted) to allow indexers to observe the final state before reclamation.
4. THE Governance_Module SHALL store the Signer_Set and Threshold in persistent storage with a 6-month TTL, consistent with the existing role storage TTL policy.

---

### Requirement 11: Error Codes

**User Story:** As a developer integrating with the governance system, I want all governance-specific failures to return distinct, documented error codes, so that clients can handle each failure mode precisely.

#### Acceptance Criteria

1. THE Governance_Module SHALL define the following new error codes in `QuickexError`: `InvalidThreshold = 502`, `InvalidSignerSet = 503`, `DuplicateSigner = 504`, `NotASigner = 505`, `ProposalAlreadyExists = 506`, `ProposalNotFound = 507`, `InvalidProposalState = 508`, `AlreadyApproved = 509`, `InsufficientApprovals = 510`, `ExpiryTooFar = 511`.
2. THE Governance_Module SHALL reuse existing error codes `NonceAlreadyUsed = 500` and `SignatureExpired = 501` for replay and expiry violations respectively.
3. THE Governance_Module SHALL reuse `Unauthorized = 200` when a direct privileged entrypoint is called outside the governance execution path.
