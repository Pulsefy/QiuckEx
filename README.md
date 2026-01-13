# QuickEx

<img width="1024" height="1024" alt="quickex no-bg (1)" src="https://github.com/user-attachments/assets/551fc54f-72ed-4fa9-9b8d-5516d8457ca8" />



[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Stellar](https://img.shields.io/badge/Built%20on-Stellar-blue)](https://stellar.org)
[![Next.js](https://img.shields.io/badge/Tech-Next.js-black)](https://nextjs.org)
[![Rust](https://img.shields.io/badge/Smart%20Contracts-Rust-orange)](https://www.rust-lang.org/)
[![Monorepo](https://img.shields.io/badge/Monorepo-TurboRepo-green)](https://turbo.build/repo)

QuickEx is a fast, privacy-focused payment link platform built on the Stellar blockchain. Create unique usernames like `quickex.to/yourname` and generate instant payment requests for USDC, XLM, or any Stellar asset. Anyone can pay via QR code or wallet — no apps required.
Powered by Stellar's sub-second settlements and X-Ray privacy (mainnet live Jan 2026).

Perfect for freelancers, creators, remittances, tips, and global P2P transfers. Low fees (<0.01¢), instant, and borderless.

## Features

### Core
- **Unique Username Links**: Claim `quickex.to/yourname` — permanent and easy to share.
- **One-Click Link Generator**: Set amount, memo, and privacy → get shareable links like `quickex.to/yourname/50`.
- **QR Code & Wallet Integration**: Auto-open Freighter/Lobstr for seamless payments.
- **Real-Time Dashboard**: View earnings, transaction history, and totals (pulled from Horizon API).

### Privacy & Security
- **X-Ray Privacy Toggle**: Shield amounts/senders with ZK proofs (testnet ready, mainnet Jan 22, 2026).
- **Scam Alerts**: Warn on suspicious links (no memo, unusual patterns).
- **Self-Custody**: Payments go directly to your wallet — no central custody.

### Advanced (v2+)
- Multi-asset support with auto-swap.
- Recurring/subscription links.
- Fiat on/off-ramps (MoneyGram, Banxa).
- Notifications (email/Telegram).

## Tech Stack
- **Frontend**: Next.js 15, Tailwind CSS, Vercel hosting.
- **Backend**: Next.js API routes, Supabase (usernames), Horizon API (transactions).
- **Blockchain**: Stellar SDK, Soroban (Rust contracts for privacy/escrow).
- **Wallet**: Freighter/Lobstr integration via WalletConnect.
- **Monorepo**: TurboRepo for shared packages (UI components, Stellar utils).

## Monorepo Structure
```
quickex/
├── apps/
│   └── quickex-frontend/  # Main Next.js app
├── packages/
│   ├── ui/                # Shared Tailwind components
│   └── stellar-sdk/       # Stellar utils (Horizon queries, wallet connect)
├── turbo.json             # Build/dev pipelines
└── pnpm-workspace.yaml    # Workspace config
```

## Quick Start

### Prerequisites
- Node.js 18+
- pnpm (recommended for monorepo)
- Stellar testnet wallet (Freighter recommended).

### Installation
1. Clone the repo:
   ```
   git clone https://github.com/pulsefy/QuickEx.git
   cd QuickEx
   ```
2. Install dependencies:
   ```
   pnpm install
   ```
3. Set up environment:
   - Create `.env.local` with `SUPABASE_URL` and `SUPABASE_ANON_KEY` (from Supabase project).
   - Add Stellar network config (testnet for dev).
4. Run locally:
   ```
   pnpm turbo run dev
   ```
   Open [http://localhost:3000](http://localhost:3000).

### Deployment
- Push to GitHub → auto-deploy on Vercel (connects to monorepo root).
- Custom domain: Add to Vercel dashboard.

## Usage
1. **Claim Username**: Connect wallet → pick name → done.
2. **Generate Link**: In dashboard, enter amount/memo → copy link/QR.
3. **Receive Payment**: Share link → payer scans/clicks → funds arrive instantly.
4. **Privacy Mode**: Toggle for X-Ray shielded txs (Rust contract deploys on mainnet).


## Contributing
We welcome contributions! Fork the repo, create a feature branch (`git checkout -b feature/amazing`), commit changes, and open a PR. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- Report bugs: Open an issue.
- Add features: Discuss in issues first.
- Monorepo tips: Use `pnpm turbo run lint` for cross-package checks.

## License
This project is MIT licensed. See [LICENSE](LICENSE) for details.

## Support & Community
- **Discord**: Join [QuickEx Community](https://discord.gg/quickex) for help/discussions.


Built with ❤️ by Pulsefy. Powered by Stellar. Questions? Let's chat! 🚀
