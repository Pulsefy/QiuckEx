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

## 8-Week MVP Roadmap & Feature Prioritization

See [docs/MVP-ROADMAP.md](docs/MVP-ROADMAP.md) for the full roadmap and priorities.

## Architecture Overview

- Backend and Contract architecture diagrams are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- See [docs/](docs/) for API, events, and payment flow documentation.

## Getting Help

- Check the [README.md](README.md) for project overview.
- Ask in Discussions or open an Issue if you’re stuck.

Happy contributing!
