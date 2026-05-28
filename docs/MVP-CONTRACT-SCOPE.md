# MVP Contract Scope Decision: QuickEx Soroban Smart Contracts

## Overview
This document defines the Soroban smart contract scope for the QuickEx Minimum Viable Product (MVP). It outlines the core candidate modules, separates on-chain enforcement from off-chain validation, details the deployment design, and specifies versioning and operational safety requirements prior to mainnet launch.

---

## 1. Candidate Modules & MVP Selection Matrix

The table below outlines the Wave 4 contract scope, evaluates each module's complexity and risk, and specifies whether it is included in the MVP on-chain scope.

| Contract Module | Wave 4 Scope Detail | MVP Status | Enforcement Strategy / Off-chain Alternative |
| :--- | :--- | :--- | :--- |
| **Core Escrow & Payments** | Deposit, partial payment, expiration-based refund, direct payout. | **IN SCOPE (On-Chain)** | Critical for trustless escrow logic. Must be fully enforced on-chain. |
| **Platform Fee Routing** | Basis-points fee collection, per-asset override tiers, collector address rotation. | **IN SCOPE (On-Chain)** | Basis-point and per-asset static fee routing is handled on-chain. Collector addresses can be rotated dynamically. |
| **Signature Replay / Nonces** | Custom off-chain signatures, nonces registry, timestamp verification. | **OUT OF SCOPE (Deferred)** | Defer custom nonce/signature verification. Use Soroban's native auth framework (`Address::require_auth`) and transaction sequence numbers for replay protection. |
| **Dispute & Arbitration** | Single-arbiter & multi-sig arbitration, voting threshold resolution. | **OUT OF SCOPE (Deferred)** | Refund-only MVP. If a transaction is disputed, funds remain locked until `expires_at` is reached, at which point the depositor can claim a refund. Dispute mediation is handled off-chain. |
| **Dynamic Oracle Fees** | Fetching price feeds from a USD oracle for dynamic fiat-pegged fee calculations. | **OUT OF SCOPE (Deferred)** | Pre-calculate fee limits off-chain via backend API and apply flat or static per-token basis-point configs on-chain. Stub oracle price fetching for MVP. |
| **On-Chain Privacy (X-Ray)** | Numeric privacy levels, stealth addresses, ephemeral key registration. | **OUT OF SCOPE (Deferred)** | Masking user profiles, matching accounts, and tracking history will be maintained off-chain by the backend in audited logs. On-chain escrows remain transparent. |
| **Hook Contract Registry** | Contract-to-contract callbacks for escrow creation/settlement/refund. | **OUT OF SCOPE (Deferred)** | Backend parses Soroban events emitted by the escrow contract to trigger webhooks off-chain. This avoids reentrancy attack vectors. |

---

## 2. Deployment Design Decisions

### Monolithic vs. Multiple Contracts
* **Decision**: Deploy **one monolithic contract** (`QuickexContract`).
* **Rationale**:
  * **Simplicity**: Single-contract deployment drastically reduces gas costs (no cross-contract calls) and limits configuration complexity.
  * **Easier Upgrades**: Upgrading a single contract is straightforward compared to coordinating migrations across multiple dependent contracts.
  * **Fewer Contract IDs**: Simplifies client-side environment configurations for frontend, mobile, and backend clients.

### Dispute Resolution Timeline
* **Decision**: Refund-only without on-chain arbitration for the MVP.
* **Arbitration Postponement**: Full M-of-N multi-sig arbitration is deferred to V2 to reduce regulatory risk and operational overhead of maintaining arbiter networks. MVP disputes rely on expiration times and off-chain mediation.

---

## 3. Upgrade & Versioning Approach

To support smooth future upgrades and keep clients compatible:

* **WASM Hash Pinning**:
  * Build targets are pinned to a specific compiled WASM hash during deployment.
  * Production clients verify the contract's WASM hash before invoking.
* **Contract Version Constants**:
  * The contract stores a `contract_version` value (`CURRENT_CONTRACT_VERSION = 1`).
  * Upgrades to newer WASM versions require invoking `migrate(admin_address)` to incrementally apply storage migrations.
* **Client Compatibility Rules**:
  * Clients query `get_version()` on startup.
  * If `get_version() != CLIENT_SUPPORTED_VERSION`, the client halts or warns the operator to prevent execution errors caused by unrecognized transaction parameters.

---

## 4. Operational Safety Requirements

Before deploying to Stellar Mainnet, the following controls must be configured:

### A. Emergency and Pause Modes
1. **Granular Operation Pausing**: 
   * The admin/operator can pause specific endpoints (e.g., pause deposits but leave withdrawals/refunds active) via `set_pause_flags`.
2. **Immutable Emergency Mode**:
   * A permanent, non-reversible emergency halt (`activate_emergency_mode`) can be triggered by the admin if an exploit is detected. 
   * Once activated, all deposits, withdrawals, and refunds are frozen indefinitely to protect remaining funds. Recovery requires a contract upgrade.

### B. Admin Model & Rotation
* **Role Separation**:
  * `Admin`: Manage upgrades, assign roles, rotate fee collector, set platform wallet.
  * `Operator`: Perform operational pauses, toggle pause flags, set fee configurations.
* **Admin Rotation**:
  * The primary admin address can be rotated using `set_admin(caller, new_admin)`.
  * For production mainnet, the admin address must be a **Stellar Multi-Sig Account** (2-of-3 threshold) held by key officers, rather than an automated backend wallet key.

---

## 5. Network Configuration & Contract ID Dependencies

Clients must resolve contract IDs dynamically based on the target network. Below is the mapping setup for the MVP:

| Network | Horizon RPC Endpoint | Native Asset Address | QuickEx Escrow Contract ID |
| :--- | :--- | :--- | :--- |
| **Local Sandbox (dev)** | `http://localhost:8000` | `CDLZFC3SYG3GHI2Dx...` | Determined at local deployment time |
| **Stellar Testnet** | `https://horizon-testnet.stellar.org` | `CDLZFC3SYG3GHI2D...` | `CD2J6K7T3YJ77QXZP3...` (Configured via Env) |
| **Stellar Futurenet** | `https://horizon-futurenet.stellar.org` | `CB5E4B3...` | `CB5E4B3N2NVSK4M2...` (Configured via Env) |
| **Stellar Mainnet** | `https://horizon.stellar.org` | `CAS3HITBYZ...` | Set post-audit upon deployment |

> [!IMPORTANT]
> To comply with PR FE-31, both frontend and backend clients must consume these contract IDs from a centralized Contract Registry service, or fall back to the environment variable `QUICKEX_CONTRACT_ID` rather than embedding them directly in client source code.
