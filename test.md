## README FILE

QuickEx
quickex no-bg (1)

QuickEx is a fast, privacy-focused payment link platform built on the Stellar blockchain. It enables users to create unique, shareable usernames (e.g., quickex.to/yourname) and generate instant payment requests for USDC, XLM, or any Stellar asset. Payments can be received via QR code or direct wallet integration—no apps required—leveraging Stellar's sub-second settlements and optional X-Ray privacy for shielded transactions (mainnet now live). With low fees (<0.01¢), it's designed for instant, borderless transfers.

This tool is ideal for freelancers invoicing clients, creators accepting tips, individuals handling remittances, or anyone facilitating global P2P payments. Whether you're a solo developer sharing a quick link for a gig or a small business streamlining donations, QuickEx prioritises simplicity, self-custody, and security without intermediaries.
Features
Core

    Unique Username Links: Claim a permanent quickex.to/yourname for easy sharing.
    One-Click Link Generator: Specify amount, memo, and privacy settings to create links like quickex.to/yourname/50.
    QR Code & Wallet Integration: Auto-opens Freighter or Lobstr for seamless payments.
    Real-Time Dashboard: Tracks earnings, history, and totals via Horizon API.

Privacy & Security

    X-Ray Privacy Toggle: Uses ZK proofs to hide amounts/senders (testnet ready; mainnet live since January 22, 2026).
    Scam Alerts: Flags suspicious links (e.g., no memo or unusual patterns).
    Self-Custody: Funds route directly to your wallet—no central holding.

Advanced (v2+)

    Multi-asset support with auto-swap.
    Recurring/subscription links.
    Fiat on/off-ramps (MoneyGram, Banxa).
    Notifications (email/Telegram).

Tech Stack

    Frontend: Next.js 15, Tailwind CSS, Vercel hosting.
    Backend: Next.js API routes (or dedicated Node.js/Express), Supabase (usernames), Horizon API (transactions).
    Mobile: React Native (for iOS/Android apps).
    Blockchain: Stellar SDK, Soroban (Rust contracts for privacy/escrow).
    Wallet: Freighter/Lobstr via WalletConnect.
    Monorepo: TurboRepo for shared packages (UI components, Stellar utils).

Repository Structure

QuickEx uses a monorepo for efficient development across apps and shared libraries. The structure features an app/ parent folder containing the core application directories (frontend, backend, mobile, contract), with shared packages for reusability. This setup allows for streamlined builds, testing, and dependency management via TurboRepo.

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

Setup Instructions
Prerequisites

Before getting started, ensure you have the following installed:

    Node.js 18+ (nodejs.org).
    pnpm (for monorepo management; install via npm install -g pnpm).
    A Stellar wallet (Freighter recommended; download from freighter.app).
    Supabase account (free tier; sign up at supabase.com).
    Git (for cloning).
    Rust toolchain (for contracts; install via rustup.rs).
    React Native CLI (for mobile; see reactnative.dev).

Installation

    Clone the repository:

    git clone https://github.com/pulsefy/QuickEx.git
    cd QuickEx

    Install dependencies across the monorepo:

    pnpm install

Environment Setup

    Create a Supabase project and retrieve your SUPABASE_URL and SUPABASE_ANON_KEY from the dashboard.
    Copy .env.example to .env.local in the root directory and populate it:

    SUPABASE_URL=your_supabase_url
    SUPABASE_ANON_KEY=your_supabase_anon_key
    NEXT_PUBLIC_STELLAR_NETWORK=testnet  # Use 'mainnet' for production

    Configure the Stellar network:
        Development: Defaults to testnet; fund your wallet at laboratory.stellar.org.
        Production: Set to mainnet in .env.local and ensure your wallet holds real assets.
    Backend (NestJS): create app/backend/.env and set STELLAR_NETWORK (default testnet). Example:

    STELLAR_NETWORK=testnet

    Allowed values: testnet, mainnet (default testnet). Supported assets are defined in app/backend/src/config/stellar.config.ts under SUPPORTED_ASSETS. To add a new asset, add a native or issued entry to SUPPORTED_ASSETS.
    For contracts: Add environment variables to app/contract/.env (e.g., STELLAR_NETWORK=testnet).
    For mobile: After installation, navigate to app/mobile and run npx pod-install (iOS) or configure the Android SDK.

Running Locally

    Launch all services using TurboRepo:

    pnpm turbo run dev

    This starts the frontend (app/frontend), backend (app/backend), and prepares contracts/mobile.
    Access the web app at http://localhost:3000.
    For the mobile app:

    cd app/mobile && npx react-native run-ios  # or run-android

    For contracts (testing/deploying):

    cd app/contract && cargo test  # Run unit tests
    # Deploy to testnet: Use Soroban CLI as per Soroban docs

Connect your wallet in the app to claim a username and test features.
Testing

Run tests to validate code quality and functionality:

    Lint and type-check the entire monorepo:

    pnpm turbo run lint
    pnpm turbo run type-check

    Execute end-to-end tests (Playwright for frontend, Jest for others):

    pnpm turbo run test:e2e

    Tests require a testnet wallet; detailed setup is in TESTING.md.
    Mobile-specific tests:

    cd app/mobile && npm test

Deployment

Deployment is automated for most components, but requires platform-specific configuration:

    Frontend and Backend (Vercel):
        Connect the GitHub repository to Vercel via the dashboard.
        Add environment variables from .env.local (e.g., Supabase keys, Stellar network).
        Pushes to main trigger auto-deploys. Set a custom domain in the Vercel project settings.

    Mobile (Expo):
        Install Expo CLI if needed: npm install -g @expo/cli.
        From app/mobile: expo publish for over-the-air updates, or build via expo build:ios / expo build:android.
        Use Expo's dashboard to manage credentials and submissions to app stores.

    Contracts (Soroban):
        Build and deploy via CI/CD (e.g., GitHub Actions in app/contract).
        For testnet: cd app/contract && soroban contract deploy --network testnet.
        For mainnet: Update network config and deploy similarly, ensuring WASM optimization.

For production readiness, always verify NEXT_PUBLIC_STELLAR_NETWORK=mainnet and conduct thorough testing. See DEPLOYMENT.md for advanced configurations like CI/CD pipelines.
Usage

    Claim Username: Connect your wallet in the app, select a name, and confirm the on-chain transaction.
    Generate Link: In the dashboard, input amount, memo, and privacy options, then copy the generated link or QR code.
    Receive Payment: Share the link; the payer clicks or scans to send funds directly to your wallet.
    Enable Privacy: Toggle X-Ray mode to shield transactions (deploys Rust contract on mainnet).

Contributing

Contributions are welcome and encouraged to help evolve QuickEx! To get started:

    Report Issues: Use GitHub Issues for bugs or feature requests. Include reproduction steps, environment details, and screenshots where possible.
    Propose Features: Start a Discussion thread to align on ideas before coding.
    Submit Pull Requests:
        Fork the repository and create a feature branch: git checkout -b feature/your-feature.
        Implement changes, ensuring they pass linting and tests.
        Commit with clear messages (e.g., "feat: add multi-asset swap support").
        Push and open a PR against main. Reference any related issues.
    Monorepo Best Practices:
        Use pnpm turbo run build to validate changes across packages.
        Update shared packages (packages/ui or packages/stellar-sdk) only when needed, and bump versions.
        Run pnpm turbo run lint --filter=... for targeted checks (e.g., --filter=app/frontend).

All contributors must adhere to the Code of Conduct and sign off commits for DCO compliance. For more, see CONTRIBUTING.md.

## TASK TO IMPLEMENT

#451 MOB-31: Release Pipeline v1 (Internal Testing Builds)
Repo Avatar Pulsefy/QiuckEx

Complexity: 200 points
Branch: feat/mobile-release-pipeline
Summary
Create a repeatable release pipeline that produces internal testing builds for contributors and QA without manual steps.
Tasks

    Set up CI to build signed internal artifacts for iOS and Android.
    Add environment matrices (dev/staging/production) without code changes.
    Ensure build metadata is visible in-app (version, build number, network).
    Add a release checklist including permissions and privacy review.
    Acceptance Criteria
    Internal builds can be produced on every release tag reliably.
    App clearly indicates build environment and network.
    Build pipeline does not expose secrets in logs.

