# Contributing Guide

Welcome to the Stella Wave project! This guide will help you set up your development environment, understand our workflow, and contribute effectively.

## Quick Start: One-Click Dev Environment

We use VS Code Dev Containers for a seamless onboarding experience. After cloning the repo, open it in VS Code and select "Reopen in Container" when prompted. The container will set up all dependencies for Soroban and Backend development.

## Environment Setup

1. **Clone the repository:**
   ```sh
   git clone <repo-url>
   cd QiuckEx
   ```
2. **Open in VS Code.**
3. **Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) if prompted.**
4. **Reopen in Container.**

The container will install:
- Node.js (LTS)
- pnpm
- Rust toolchain (for Soroban)
- Soroban CLI
- Docker (for local services)
- All backend/frontend dependencies

## Manual Environment Setup (Without Dev Containers)

If you prefer to set up the environment manually on your host machine:

### 1. TypeScript/Node
1. Install Node.js (LTS).
2. Install `pnpm` globally (`npm i -g pnpm`).
3. Run `pnpm install` in the repository root.
4. Start the frontend/backend servers via TurboRepo:
   ```bash
   pnpm turbo run dev
   ```

### 2. Rust/Soroban
1. Install Rust via `rustup`:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup default stable
   rustup target add wasm32-unknown-unknown
   ```
2. Build the contracts:
   ```bash
   cd app/contract
   cargo build --target wasm32-unknown-unknown --release
   ```

## Branch Naming

- Feature branches: `feat/<short-description>`
- Bugfix branches: `fix/<short-description>`
- Docs branches: `docs/<short-description>`
- Chores: `chore/<short-description>`

## Pull Request Guidelines

- Reference the issue number in your PR description.
- Add clear, descriptive titles.
- Ensure all tests pass before requesting review.
- Follow the [Conventional Commits](https://www.conventionalcommits.org/) style.
- Add/Update documentation as needed.

## Accessibility

The frontend is checked in CI with `eslint-plugin-jsx-a11y` (errors on the
QR/payment flow, warnings elsewhere) and `jest-axe`/`axe-core` audits of the
payment link generator, pay page, and payment-state components — see
[app/frontend/CONTRIBUTING.md](app/frontend/CONTRIBUTING.md#accessibility)
for the checklist to follow when touching UI.

## 8-Week MVP Roadmap & Feature Prioritization

See [docs/MVP-ROADMAP.md](docs/MVP-ROADMAP.md) for the full roadmap and priorities.

## Architecture Overview

- Backend and Contract architecture diagrams are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- Check [docs/CAPABILITY-MAP.md](docs/CAPABILITY-MAP.md) to see which flows are Live, Partial, Mocked, or Experimental before building on them.
- Before adding backend code, read [docs/BACKEND-MODULE-MAP.md](docs/BACKEND-MODULE-MAP.md) — it says what each module under `app/backend/src/` owns, which modules may depend on which, and how to decide whether your change extends an existing module or needs a new one.
- Adding or translating user-facing copy? See [docs/LOCALIZATION-GUIDE.md](docs/LOCALIZATION-GUIDE.md) for how strings work across the frontend and mobile clients.
- Operating a testnet environment? [docs/TESTNET-INCIDENT-RUNBOOK.md](docs/TESTNET-INCIDENT-RUNBOOK.md) covers detection, mitigation, and rollback per incident scenario.
- See [docs/](docs/) for API, events, and payment flow documentation.

## Getting Help

- Check the [README.md](README.md) for project overview.
- Ask in Discussions or open an Issue if you’re stuck.

Happy contributing!


# Supabase Schema & Database Migrations Reference

> **Related Documents**: 
> - For backend service ownership and module boundaries, see [Backend Module Map](./BACKEND-MODULE-MAP.md).
> - For contributor guidelines and PR expectations, see [Contributing Guide](../CONTRIBUTING.md).

---

## 1. Overview

The `app/backend/supabase/migrations/` directory houses over 46 schema migrations powering QuickEx. Because the application combines traditional backend microservices with Stellar blockchain state synchronization, abuse detection, outbox messaging, and notification templating, this document serves as the definitive architecture reference for all database tables, ownership, relationships, and migration safety protocols.

---

## 2. Core Tables, Ownership & Purpose

| Table Name | Owning Backend Module | Scope | Description & Purpose |
| :--- | :--- | :--- | :--- |
| `abuse_signals` | `SecurityModule` | Global | Tracks anomalous IP requests, brute-force attempts, and rate-limit violations for automated security flagging and blocking. |
| `reconciliation_runs` | `SettlementModule` | Global | Logs automated financial and on-chain asset reconciliation runs, tracking balance discrepancies between database ledgers and Stellar network state. |
| `notification_template_versions` | `NotificationsModule` | Global | Stores version-controlled email, push, and SMS notification templates to ensure auditability of outbound communications. |
| `contract_specs` | `Web3Module` | Global | Caches Soroban smart contract specifications, interface schemas, and ABI definitions for backend validation. |
| `outbox_table` | `EventBusModule` | Global | Implements the Transactional Outbox pattern, ensuring reliable asynchronous message publishing to Redis/Kafka queues. |
| `branch_deployments` | `PreviewModule` | **Preview / Testnet Only** | Tracks ephemeral preview environment deployments, preview URLs, and associated staging database forks. |

---

## 3. Key Relationships & Foreign Keys (ERD Reference)

await this.notificationService.dispatch({
  type: NOTIFICATION_TYPES.STAKING_REWARD_CLAIMED,
  recipientId: user.id,
  payload: { amount: '150', tokenSymbol: 'USDC' },
});


# Auth & Authorization Flow Reference

> **Related Document**: For repository secret scanning, pre-commit hooks, and credential security guidelines, please refer to [Security Guidelines](./security.md).

---

## 1. Authentication Paths Overview

QuickEx supports three distinct authentication mechanisms tailored for different client types and integration patterns:

| Authentication Type | Primary Use Case | Mechanism | Target Clients |
| :--- | :--- | :--- | :--- |
| **Wallet Signature Auth** | Web3 Identity Verification | Challenge-response cryptographic signature verification using Stellar/Soroban keypairs. | Web & Mobile DApp Users |
| **JWT (JSON Web Token)** | Session & User Access | Standard Bearer token issued upon successful wallet sign-in or OAuth authentication. | Frontend App / Mobile Client |
| **API Key Auth** | Programmatic / Service-to-Service | Secret API key header (`X-API-Key`) validated against hashed database storage with scoped privileges. | External Integrators & Bots |

---

## 2. Guards & Decorators Reference

Located in `app/backend/src/auth/`, guards and decorators secure endpoints and enforce granular permission policies.

### 2.1 Guards
* **`ApiKeyGuard` (`api-key.guard.ts`)**: Intercepts requests carrying `X-API-Key`, validates the key hash against the database, checks expiration, and attaches associated scopes to the request context.
* **`OrganizationRoleGuard` (`organization-role.guard.ts`)**: Verifies that the authenticated user possesses the required organizational role (e.g., `owner`, `admin`, `member`) within the requested organization scope.
* **`CustomThrottlerGuard` (`custom-throttler.guard.ts`)**: Applies dynamic, tier-based rate limiting using Redis sliding windows based on rate-limit groups.

### 2.2 Decorators & Usage Example

```typescript
import { Controller, Get, Post, UseGuards } from '@nestjs/common';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { OrganizationRoleGuard } from '../auth/guards/organization-role.guard';
import { CustomThrottlerGuard } from '../auth/guards/custom-throttler.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { RequireOrgRole } from '../auth/decorators/require-org-role.decorator';
import { RateLimitGroup } from '../auth/decorators/rate-limit-group.decorator';

@Controller('api/v1/vaults')
@UseGuards(CustomThrottlerGuard)
export class VaultController {

  @Post('transfer')
  @UseGuards(ApiKeyGuard)
  @RequireScopes('vault:write', 'funds:transfer')
  @RateLimitGroup('strict-transactions') // Max 10 req/min
  async transferFunds() {
    // Executes only if API key has both scopes and rate limit permits
  }

  @Get('audit-logs')
  @UseGuards(OrganizationRoleGuard)
  @RequireOrgRole('admin')
  @RateLimitGroup('standard-read') // Max 100 req/min
  async getAuditLogs() {
    // Executes only if user is an Org Admin
  }
}