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

### Authentication Patterns
- Use `owner.require_auth()` for owner-only operations
- Authentication must happen before any state changes
- Document auth requirements in function docstrings

### Event Emission
- Emit events for all state-changing operations
- Include relevant data in event payloads (owner, new_state, timestamp)
- Use descriptive event names (e.g., `PrivacyToggled`)

### Error Handling
- Return typed errors from `errors.rs` module
- Use appropriate error types (`Unauthorized`, `InvalidInput`, `StorageError`)
- Handle errors gracefully in calling code

## Contract Architecture

### Module Structure
```
src/
├── lib.rs           # Main contract and public API
├── privacy.rs       # Privacy toggle logic and storage
├── events.rs        # Event definitions and publishing
├── errors.rs        # Typed error definitions
└── test.rs          # Unit tests
```

### Privacy Toggle (v0) Implementation
- **Storage**: Per-owner boolean flags in persistent storage
- **Access Control**: Owner-only mutation via `require_auth()`
- **Events**: `PrivacyToggled` event emission on state changes
- **Errors**: Typed error returns for auth failures
```