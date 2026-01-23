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

### Quality Assurance

#### Code Formatting
- Use `cargo fmt` to format code before committing
- CI will check formatting with `cargo fmt --all -- --check`
- Follow standard Rust formatting conventions

#### Linting
- Run `cargo clippy --all-targets --all-features -- -D warnings` before committing
- Fix all clippy warnings and errors
- CI will enforce clippy checks

#### Testing
- Write comprehensive unit tests for all functions
- Run `cargo test` to ensure all tests pass
- CI will run the full test suite
- Aim for good test coverage

#### Pre-commit Checks
```bash
# Run all quality checks locally
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test
```

## Pull Request Checklist

Before submitting a PR, ensure:

- [ ] Code is formatted with `cargo fmt`
- [ ] All clippy warnings are resolved
- [ ] All tests pass (`cargo test`)
- [ ] New functionality includes appropriate tests
- [ ] Documentation is updated if needed
- [ ] Commit messages follow conventional format
- [ ] PR description explains the changes and why they're needed

## Development Workflow

1. **Setup**: Install prerequisites and ensure local environment works
2. **Branch**: Create a feature branch from `main`
3. **Develop**: Make changes following code standards
4. **Test**: Run quality checks and tests locally
5. **Commit**: Use clear, descriptive commit messages
6. **Push**: Push branch and create PR
7. **Review**: Address review feedback
8. **Merge**: PR is merged after CI passes and approval

## Debugging CI Issues

If CI fails, you can debug locally:

```bash
# Reproduce CI environment
cd app/contract

# Check formatting
cargo fmt --all -- --check

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test

# Build for WASM target
cargo build --target wasm32-unknown-unknown --release
```

Common issues:
- **Formatting**: Run `cargo fmt` to fix
- **Clippy**: Address the specific warnings shown
- **Tests**: Ensure tests work in isolated environment
- **Build**: Check for WASM-specific compilation issues