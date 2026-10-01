# QuickEx

<img width="1024" height="1024" alt="quickex no-bg (1)" src="https://github.com/user-attachments/assets/551fc54f-72ed-4fa9-9b8d-5516d8457ca8" />

QuickEx is a fast, privacy-focused payment link platform built on the Stellar blockchain. It enables users to create unique, shareable usernames (e.g., `quickex.to/yourname`) and generate instant payment requests for USDC, XLM, or any Stellar asset. Payments can be received via QR code or direct wallet integration—no apps required—leveraging Stellar's sub-second settlements and optional X-Ray privacy for shielded transactions (mainnet now live). With low fees (<0.01¢), it's designed for instant, borderless transfers.

This tool is ideal for freelancers invoicing clients, creators accepting tips, individuals handling remittances, or anyone facilitating global P2P payments. Whether you're a solo developer sharing a quick link for a gig or a small business streamlining donations, QuickEx prioritises simplicity, self-custody, and security without intermediaries.

## Features

### Core
- **Unique Username Links**: Claim a permanent `quickex.to/yourname` for easy sharing.
- **One-Click Link Generator**: Specify amount, memo, and privacy settings to create links like `quickex.to/yourname/50`.
- **QR Code & Wallet Integration**: Auto-opens Freighter or Lobstr for seamless payments.
- **Real-Time Dashboard**: Tracks earnings, history, and totals via Horizon API.

### Privacy & Security
- **X-Ray Privacy Toggle**: Uses ZK proofs to hide amounts/senders (testnet ready; mainnet live since January 22, 2026).
- **Scam Alerts**: Flags suspicious links (e.g., no memo or unusual patterns).
- **Self-Custody**: Funds route directly to your wallet—no central holding.

### Advanced (v2+)
- Multi-asset support with auto-swap.
- Recurring/subscription links.
- Fiat on/off-ramps (MoneyGram, Banxa).
- Notifications (email/Telegram)..

## Tech Stack
- **Frontend**: Next.js 15, Tailwind CSS, Vercel hosting.
- **Backend**: Next.js API routes (or dedicated Node.js/Express), Supabase (usernames), Horizon API (transactions).
- **Mobile**: React Native (for iOS/Android apps).
- **Blockchain**: Stellar SDK, Soroban (Rust contracts for privacy/escrow).
- **Wallet**: Freighter/Lobstr via WalletConnect.
- **Monorepo**: TurboRepo for shared packages (UI components, Stellar utils).

## Repository Structure
QuickEx uses a monorepo for efficient development across apps and shared libraries. The structure features an `app/` parent folder containing the core application directories (frontend, backend, mobile, contract), with shared packages for reusability. This setup allows for streamlined builds, testing, and dependency management via TurboRepo.

```
quickex/
├── app/
│   ├── frontend/          # Next.js app (web dashboard and link generator)
│   ├── backend/           # API server (Node.js/Express or Next.js API routes; handles usernames, transactions)
│   ├── mobile/            # React Native app (iOS/Android for on-the-go payments)
│   └── contract/          # Soroban Rust contracts (privacy/escrow logic)
├── packages/
│   ├── ui/                # Shared Tailwind components
│   └── stellar-sdk/       # Stellar utils (Horizon queries, wallet connect)
├── turbo.json             # Build/dev pipelines (configured for app/ subfolders)
└── pnpm-workspace.yaml    # Workspace config (includes app/* and packages/*)
```



## Setup Instructions

### Prerequisites
Before getting started, ensure you have the following installed:
- Node.js 18+ ([nodejs.org](https://nodejs.org)).
- pnpm (for monorepo management; install via `npm install -g pnpm`).
- A Stellar wallet (Freighter recommended; download from [freighter.app](https://freighter.app)).
- Supabase account (free tier; sign up at [supabase.com](https://supabase.com)).
- Git (for cloning).
- Rust toolchain (for contracts; install via [rustup.rs](https://rustup.rs)).
- React Native CLI (for mobile; see [reactnative.dev](https://reactnative.dev/docs/environment-setup)).

### Installation & Local Development Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/pulsefy/QuickEx.git
   cd QuickEx
   ```

2. **TypeScript/Node Setup**:
   Install dependencies across the monorepo using `pnpm`:
   ```bash
   pnpm install
   ```
   Start the local development server (Frontend + Backend):
   ```bash
   pnpm turbo run dev
   ```

3. **Rust/Soroban Setup** (for Contracts):
   Ensure you have the Rust toolchain installed:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup default stable
   rustup target add wasm32-unknown-unknown
   ```
   Build the contracts locally:
   ```bash
   cd app/contract
   cargo build --target wasm32-unknown-unknown --release
   ```

### Environment Setup
1. Create a Supabase project and retrieve your `SUPABASE_URL` and `SUPABASE_ANON_KEY` from the dashboard.
2. Copy `.env.example` to `.env.local` in the root directory and populate it:
   ```
   SUPABASE_URL=your_supabase_url
   SUPABASE_ANON_KEY=your_supabase_anon_key
   NEXT_PUBLIC_STELLAR_NETWORK=testnet  # Use 'mainnet' for production
   ```
3. Configure the Stellar network:
   - **Development**: Defaults to testnet; fund your wallet at [laboratory.stellar.org](https://laboratory.stellar.org).
   - **Production**: Set to `mainnet` in `.env.local` and ensure your wallet holds real assets.
4. Backend (NestJS): create `app/backend/.env` and set `STELLAR_NETWORK` (default `testnet`).
   Example:
   ```
   STELLAR_NETWORK=testnet
   ```
   Allowed values: `testnet`, `mainnet` (default `testnet`).
   Supported assets are defined in `app/backend/src/config/stellar.config.ts` under `SUPPORTED_ASSETS`.
   To add a new asset, add a native or issued entry to `SUPPORTED_ASSETS`.
5. For contracts: Add environment variables to `app/contract/.env` (e.g., `STELLAR_NETWORK=testnet`).
6. For mobile: After installation, navigate to `app/mobile` and run `npx pod-install` (iOS) or configure the Android SDK.

### Running Locally
1. Launch all services using TurboRepo:
   ```
   pnpm turbo run dev
   ```
   This starts the frontend (`app/frontend`), backend (`app/backend`), and prepares contracts/mobile.
2. Access the web app at [http://localhost:3000](http://localhost:3000).
3. For the mobile app:
   ```
   cd app/mobile && npx react-native run-ios  # or run-android
   ```
4. For contracts (testing/deploying):
   ```
   cd app/contract && cargo test  # Run unit tests
   # Deploy to testnet: Use Soroban CLI as per Soroban docs
   ```

Connect your wallet in the app to claim a username and test features.

### Testing
Run tests to validate code quality and functionality:
1. Lint and type-check the entire monorepo:
   ```
   pnpm turbo run lint
   pnpm turbo run type-check
   ```
2. Execute end-to-end tests (Playwright for frontend, Jest for others):
   ```
   pnpm turbo run test:e2e
   ```
   Tests require a testnet wallet; detailed setup is in [TESTING.md](TESTING.md).
3. Mobile-specific tests:
   ```
   cd app/mobile && npm test
   ```

### Deployment
Deployment is automated for most components, but requires platform-specific configuration:

1. **Frontend and Backend (Vercel)**:
   - Connect the GitHub repository to Vercel via the dashboard.
   - Add environment variables from `.env.local` (e.g., Supabase keys, Stellar network).
   - Pushes to `main` trigger auto-deploys. Set a custom domain in the Vercel project settings.

2. **Mobile (Expo)**:
   - Install Expo CLI if needed: `npm install -g @expo/cli`.
   - For internal testing builds, use EAS and the GitHub workflow defined in `./.github/workflows/mobile-release.yml`.
   - From `app/mobile`: run `npx eas build --profile production --platform android` or `npx eas build --profile production --platform ios` when credentials are configured.
   - Ensure `EAS_TOKEN` is stored in GitHub secrets and not exposed in logs.

3. **Contracts (Soroban)**:
   - Build and deploy via CI/CD (e.g., GitHub Actions in `app/contract`).
   - For testnet: `cd app/contract && soroban contract deploy --network testnet`.
   - For mainnet: Update network config and deploy similarly, ensuring WASM optimization.

For production readiness, always verify `NEXT_PUBLIC_STELLAR_NETWORK=mainnet` and conduct thorough testing. See [DEPLOYMENT.md](DEPLOYMENT.md) for advanced configurations like CI/CD pipelines.

## Usage
1. **Claim Username**: Connect your wallet in the app, select a name, and confirm the on-chain transaction.
2. **Generate Link**: In the dashboard, input amount, memo, and privacy options, then copy the generated link or QR code.
3. **Receive Payment**: Share the link; the payer clicks or scans to send funds directly to your wallet.
4. **Enable Privacy**: Toggle X-Ray mode to shield transactions (deploys Rust contract on mainnet).

## Contributing
Contributions are welcome and encouraged to help evolve QuickEx! To get started:

- **Report Issues**: Use GitHub Issues for bugs or feature requests. Include reproduction steps, environment details, and screenshots where possible.
- **Propose Features**: Start a Discussion thread to align on ideas before coding.
- **Submit Pull Requests**:
  1. Fork the repository and create a feature branch: `git checkout -b feature/your-feature`.
  2. Implement changes, ensuring they pass linting and tests.
  3. Commit with clear messages (e.g., "feat: add multi-asset swap support").
  4. Push and open a PR against `main`. Reference any related issues.
- **Monorepo Best Practices**:
  - Use `pnpm turbo run build` to validate changes across packages.
  - Update shared packages (`packages/ui` or `packages/stellar-sdk`) only when needed, and bump versions.
  - Run `pnpm turbo run lint --filter=...` for targeted checks (e.g., `--filter=app/frontend`).
- **Database Schema**: Before writing a query or a new Supabase migration, read [docs/DATA-MODEL.md](docs/DATA-MODEL.md). It has the ER diagram, the table-by-table data dictionary with owning modules and keys, and an explanation of why migrations are split across folders. Any migration that changes tables or keys must update that document in the same PR. [docs/BACKEND-MODULE-MAP.md](docs/BACKEND-MODULE-MAP.md) explains what each backend module owns and which modules may import which.

All contributors must adhere to the [Code of Conduct](CODE_OF_CONDUCT.md) and sign off commits for DCO compliance. For more, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Support & Community
- Join the [QuickEx Discord](https://discord.gg/gBmApTNVV) for real-time help, discussions, and updates.
- Have questions? Open an issue or DM @pulsefy.

Built with ❤️ by Pulsefy. Powered by Stellar. 🚀

# Local Development

## Prerequisites

Install the following:

- Rust (stable)
- Cargo
- Node.js 20+
- npm or pnpm
- PostgreSQL
- Redis
- Stellar CLI (if developing smart contracts)

---

## Clone the Repository

```bash
git clone https://github.com/Pulsefy/QiuckEx.git

cd QiuckEx
```

---

## Configure Environment

Copy the example configuration.

```bash
cp .env.example .env
```

Update the values for:

- DATABASE_URL
- JWT secrets
- Stripe keys
- Stellar secret/public keys
- Horizon endpoint
- Soroban RPC endpoint

---

## Install Dependencies

Backend

```bash
npm install
```

or

```bash
pnpm install
```

Rust contracts

```bash
cargo build
```

---

## Database

Run database migrations.

Prisma

```bash
npx prisma migrate dev
```

or

TypeORM

```bash
npm run migration:run
```

(Use the command appropriate for the repository.)

---

## Start Backend

```bash
npm run dev
```

---

## Run Smart Contract Tests

```bash
cargo test
```

---

## Run Backend Tests

```bash
npm test
```

---

## Formatting

TypeScript

```bash
npm run lint

npm run format
```

Rust

```bash
cargo fmt

cargo clippy

cargo test
```

---

## Required Environment Variables

| Variable | Purpose |
|----------|----------|
| DATABASE_URL | PostgreSQL connection |
| JWT_SECRET | Authentication signing key |
| STRIPE_SECRET_KEY | Stripe payment processing |
| STRIPE_WEBHOOK_SECRET | Stripe webhook verification |
| STELLAR_SECRET_KEY | Stellar wallet signing |
| STELLAR_PUBLIC_KEY | Stellar account |
| STELLAR_HORIZON_URL | Horizon API |
| STELLAR_RPC_URL | Soroban RPC endpoint |
| REDIS_URL | Redis cache |


# Developer Guide: Feature Flags & Contract-Write Safety Guards

> **Related Document**: For operator-facing incident response instructions (such as how to flip emergency kill switches during an active live incident), please refer to the [Testnet Incident Runbook](./TESTNET-INCIDENT-RUNBOOK.md).

---

## 1. Overview

The backend core includes a robust safety and feature gating architecture located in `app/backend/src/feature-flags/`. This directory contains critical security layers designed to protect Stellar smart contract interactions, restrict unauthorized contract writes during emergencies, and control feature rollout.

Key components in this module:
* **Feature Flag Service & Controller**: Dynamically evaluates feature toggles.
* **`@RequiresFlag(flagName)`**: Route decorator used to gate controllers and endpoints.
* **Contract-Write Kill Switch Constants (`contract-write-kill-switch.constants.ts`)**: Global master flags to instantly halt contract-writing operations.
* **Emergency Entrypoint Allowlist & Registry (`emergency-entrypoint-registry.ts`, `emergency-entrypoint-allowlist.guard.ts`)**: Defines whitelisted critical functions that bypass standard restrictions during specific administrative recovery scenarios.
* **Network Safety Guard (`network-safety.guard.ts`)**: Ensures testnet/mainnet safety boundaries are strictly enforced.

---

## 2. Adding a New Feature Flag End-to-End

To introduce a new feature and gate access across backend and client layers, follow these steps:

### Step 2.1: Register the Flag Name
Add your new flag identifier to the feature flags configuration or database seeding file:

```typescript
// app/backend/src/feature-flags/constants/feature-flags.constants.ts
export const FEATURE_FLAGS = {
  STAKING_V2_ENABLED: 'staking_v2_enabled',
  NEW_VAULT_DEPOSIT: 'new_vault_deposit', // <--- Your new flag
} as const;


# ==============================================================================
# QuickEx Backend Environment Configuration Reference
# ==============================================================================
# This file serves as the definitive template (.env.example) reconciled against
# app/backend/src/config/env.schema.ts. 
#
# Related Documentation:
# - For core network URLs and contract IDs, see docs/RUNTIME-CONFIG-MATRIX.md.
# - For subsystem breakdowns and environment requirements, see Section 2 below.
# ==============================================================================

# ==============================================================================
# 1. CORE APPLICATION & SERVER
# ==============================================================================
NODE_ENV=development                       # Required: development | test | staging | production
PORT=3000                                  # Optional: Port number (default: 3000)
API_PREFIX=api/v1                          # Optional: Global route prefix

# ==============================================================================
# 2. DATABASE & REDIS CACHING
# ==============================================================================
DATABASE_URL=postgresql://user:pass@localhost:5432/quickex?schema=public  # Required (All envs)
REDIS_URL=redis://localhost:6379           # Required for rate limiting & queues (All envs)

# ==============================================================================
# 3. STELLAR & WEB3 CONTRACT CONFIGURATION
# ==============================================================================
STELLAR_NETWORK=testnet                    # Required: testnet | mainnet
STELLAR_RPC_URL=https://soroban-testnet.stellar.org:443  # Required
STELLAR_ADMIN_SECRET_KEY=S...              # Required in Staging/Production for admin signing
USDC_ASSET_ISSUER=G...                     # Required: USDC asset issuer public key on Stellar

# ==============================================================================
# 4. SECURITY, RATE LIMITING & ABUSE SIGNALS
# ==============================================================================
JWT_SECRET=super-secret-jwt-key            # Required (All envs)
JWT_EXPIRES_IN=7d                          # Optional
RATE_LIMIT_TTL=60                          # Optional (Seconds)
RATE_LIMIT_LIMIT=100                       # Optional (Max requests per TTL)
RATE_LIMIT_ALLOWLIST_IPS=127.0.0.1,::1     # Optional: Comma-separated trusted IPs
ABUSE_SIGNAL_THRESHOLD=10                  # Optional: Trigger threshold for security flags
ABUSE_SIGNAL_WINDOW_SEC=300                # Optional: Time window for abuse monitoring

# ==============================================================================
# 5. TELEMETRY & OBSERVABILITY (OTEL)
# ==============================================================================
OTEL_ENABLED=false                         # Optional: true | false
OTEL_SERVICE_NAME=quickex-backend          # Required if OTEL_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317  # Required if OTEL_ENABLED=true

# ==============================================================================
# 6. QUEUES, DLQ & EXPORT SERVICES
# ==============================================================================
DLQ_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...  # Optional: Dead Letter Queue alerting
EXPORT_DOWNLOAD_SECRET=secure-export-secret-key             # Required for signed report downloads
MOBILE_MIN_SUPPORTED_VERSION=1.0.0                          # Required: Minimum client app version

# ==============================================================================
# 7. DEPRECATED / REMOVED FIELDS (Historical Reference)
# ==============================================================================
# STRIPE_SECRET_KEY=                       # REMOVED: Replaced by native Stellar/Soroban payments
# PAYMENT_PROVIDER=                        # REMOVED: Legacy fiat payment switch
# USDC_TOKEN_CONTRACT=                     # REMOVED: Replaced by dynamic registry config

# Mobile Deep Link Routing & Debug Guide

> **Related Documents**:
> - For OS-level verification files, Apple App Site Association (`apple-app-site-association`), and Android Digital Asset Links (`assetlinks.json`), please refer to the root [Universal Links Implementation Summary](../UNIVERSAL_LINKS_IMPLEMENTATION_SUMMARY.md) and [Universal Links Testing Guide](../UNIVERSAL_LINKS_TESTING_GUIDE.md).
> - This document focuses exclusively on **in-app routing, URL parsing, target screens, and developer debugging**.

---

## 1. Overview & Supported Link Formats

The QuickEx mobile application (`app/mobile/`) supports both custom URI schemes for local testing and secure Universal/App Links for production routing.

### Supported Schemes & Domains
* **Custom URI Scheme**: `quickex://` (e.g., `quickex://payment-confirmation?txId=123&amount=50`)
* **Universal Links / App Links**: `https://app.quickex.io/` or preview domain variants configured in `app/mobile/app.json` under `expo.ios.associatedDomains` and `expo.android.intentFilters`.

---

## 2. In-App Routing & Parsing (`app/_layout.tsx`)

Incoming deep links are intercepted and parsed within `app/mobile/app/_layout.tsx` using Expo Router's deep linking listener hooks.

## 3. Deep-Link Target Screens & Parameter Validation

### 3.1 Payment Confirmation Screen (`app/mobile/app/payment-confirmation.tsx`)
This screen handles post-transaction redirect flows from Stellar/Soroban wallet signatures or fiat gateways.

* **Expected Query Parameters**:
  * `txId` (string, required): The Stellar transaction hash.
  * `amount` (string, optional): The transferred token amount.
  * `status` (string, optional): `success` | `failed`.
* **Malformed Input Handling**:
  * If `txId` is missing or malformed, the screen catches the validation error, displays a fallback warning banner (`"Invalid or missing transaction identifier"`), and renders a "Return to Dashboard" button instead of crashing or attempting verification polling.

---

## 4. Deep Link Debugging Tool (`app/mobile/app/deep-link-debug.tsx`)

To assist developers during feature development, a dedicated debug screen is available at `/deep-link-debug` (typically enabled in development builds).

### Purpose & Features
* **Live URI Inspection**: Displays the exact raw deep link string that launched the app or was last parsed.
* **Parameter Breakdown**: Dynamically renders a key-value JSON tree of all extracted query parameters and route segments.
* **Manual Simulator / Trigger**: Allows developers to input custom test URIs (e.g., `quickex://payment-confirmation?txId=test_hash_999&amount=100`) and instantly execute router navigation to verify screen rendering without needing external CLI tools or physical device pushes.

### How to Use During Development
1. Run the mobile app in development mode: `npx expo start`
2. Navigate to the **Deep Link Debugger** tab (`/deep-link-debug`).
3. Type or paste your target deep link URL into the input field and press **Simulate Route**.
4. Observe parsing outputs and verify that the target screen handles parameters correctly.

---

### Implementation Metadata & Commit

```text
docs(mobile): add mobile deep link routing, parsing and debug guide (#1142)

- Document custom URI schemes (quickex://) and Universal Link integration configured in app.json
- Detail in-app link interception and routing inside app/_layout.tsx
- Explain payment-confirmation.tsx parameter contracts and robust malformed input handling
- Describe deep-link-debug.tsx simulator usage for developer workflows and cross-link root documents