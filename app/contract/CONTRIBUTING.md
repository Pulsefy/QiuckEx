# Contributing to QuickSilver Privacy Contract

Thank you for your interest in contributing to the QuickSilver privacy contract! This document outlines the development guidelines, code standards, and contribution workflow for this Soroban smart contract.

## 📋 Development Guidelines

### Prerequisites
- Rust 1.70 or higher
- Soroban CLI (`cargo install soroban-cli`)
- wasm32-unknown-unknown target (`rustup target add wasm32-unknown-unknown`)

### Code Style

#### Naming Conventions
- **Structs**: `PascalCase` (e.g., `QuickSilverContract`)
- **Functions**: `snake_case` (e.g., `enable_privacy`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `MAX_PRIVACY_LEVEL`)
- **Variables**: `snake_case` (e.g., `account_address`)
- **Storage Keys**: Descriptive strings (e.g., `"privacy_level"`)

#### Import Order
```rust
// 1. External crates
use soroban_sdk::{contract, contractimpl, Env};

// 2. Internal modules (if any)
// use crate::types::PrivacyLevel;

// 3. Module declarations
mod test;
```