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
