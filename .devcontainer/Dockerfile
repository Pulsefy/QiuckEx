FROM mcr.microsoft.com/devcontainers/base:ubuntu-22.04

# Install Node.js, pnpm, Rust, Soroban CLI, and other dependencies
RUN apt-get update && \
    apt-get install -y curl git build-essential docker.io && \
    curl -fsSL https://get.pnpm.io/install.sh | sh - && \
    curl https://sh.rustup.rs -sSf | sh -s -- -y && \
    . $HOME/.cargo/env && \
    cargo install --locked --git https://github.com/stellar/soroban-tools soroban-cli && \
    apt-get clean

ENV PATH="/root/.cargo/bin:/root/.local/share/pnpm:$PATH"
