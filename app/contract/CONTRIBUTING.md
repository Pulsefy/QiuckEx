# Contributing to QuickEx Privacy Contract

Thank you for your interest in contributing to the QuickEx privacy contract! This document outlines the development guidelines, code standards, and contribution workflow for this Soroban smart contract.

## 📋 Development Guidelines

### Prerequisites
- Rust 1.70 or higher
- Soroban CLI (`cargo install soroban-cli`)
- wasm32-unknown-unknown target (`rustup target add wasm32-unknown-unknown`)

### Code Style

#### Naming Conventions
- **Structs**: `PascalCase` (e.g., `QuickexContract`)
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

## Amount Commitment Design (X-Ray Privacy)

### Overview

The amount commitment module (`src/commitment.rs`) provides placeholder functions for shielding transaction amounts in X-Ray privacy flows. This is intentionally a deterministic, non-cryptographic stub to allow API and UX development before full zero-knowledge proof integration.

### Design Goals

1. **Deterministic Hashing**: Same inputs always produce identical hashes (useful for audits and round-trip verification)
2. **Domain Separation**: Owner address included in serialization to prevent cross-owner commitment reuse
3. **Extensibility**: Clear path to upgrade to real ZK commitments (Pedersen, Poseidon) without API changes
4. **Resource Safety**: Bounds on salt length (256 bytes max) to prevent DoS

### Serialization Format

```
commitment = SHA256( owner_xdr_bytes || amount_big_endian_i128 || salt_bytes )
```

- **Owner**: XDR-encoded Address (varies by implementation; typically ~40-80 bytes)
- **Amount**: i128 in big-endian (16 bytes, signed)
- **Salt**: User-provided randomness (0-256 bytes)

**Result**: 32-byte SHA256 hash

### Security Caveats

⚠️ **IMPORTANT**: These commitments are **NOT** cryptographically hiding. They are:

- **Deterministic**: Same amount + salt always produce the same commitment
- **Linkable**: An observer can correlate commitments to amounts
- **Not Zero-Knowledge**: No range proof or amount hiding; just a hash
- **Temporary**: Intended as a placeholder for v0.1 only

**Do NOT** deploy this for real privacy. Mark as experimental in UX.

### Input Validation

Functions enforce:

- **Non-negative amounts**: Negative amounts panic; validate before calling
- **Salt length ≤ 256 bytes**: Prevents unbounded storage/computation costs
- **No null/empty address**: Soroban SDK Address validation handles this

### Future Roadmap

| Version | Approach | Privacy | Notes |
|---------|----------|---------|-------|
| **v0.1** | SHA256 hash | None | Placeholder for API/UX shaping |
| **v0.2** | Pedersen commitments | Hiding (additive) | With range proofs for amounts |
| **v1.0** | Zether or Circom | Full shielding | Confidential amounts + transfers |

### Testing Guidelines

When adding commitment tests:

1. **Success paths**: Round-trip create → verify with same inputs
2. **Tampering detection**: Verify fails if amount, salt, or owner differs
3. **Edge cases**: Zero amounts, empty salts, large amounts (i128::MAX), many owners
4. **Determinism**: Same inputs produce identical hashes (important for auditability)
5. **Validation errors**: Test panics for negative amounts and oversized salts (use `#[should_panic]`)

### Example Test Pattern

```rust
#[test]
fn test_commitment_round_trip() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let amount = 1_000_000i128;
    let salt = Bytes::from_slice(&env, &[1, 2, 3]);

    // Create
    let commitment = create_amount_commitment(&env, &owner, amount, &salt);

    // Verify
    assert!(verify_amount_commitment(&env, &commitment, &owner, amount, &salt));
}

#[test]
fn test_commitment_tampering_detection() {
    // ... setup ...
    
    // Verify fails with modified amount
    assert!(!verify_amount_commitment(&env, &commitment, &owner, amount + 1, &salt));
}

#[test]
#[should_panic(expected = "Amount must be non-negative")]
fn test_commitment_rejects_negative_amount() {
    // ... setup ...
    let _ = create_amount_commitment(&env, &owner, -1i128, &salt);
}
```

### Code Review Focus

When reviewing commitment PRs:

1. ✅ **Serialization**: Owner + amount + salt always in same order
2. ✅ **Hashing**: Uses `Env::crypto().sha256()` (deterministic, standard)
3. ✅ **Validation**: Enforces amount ≥ 0 and salt length ≤ 256
4. ✅ **Documentation**: Clearly states "not real privacy" and lists caveats
5. ✅ **Tests**: Cover success, tampering, and edge cases

### Migration Path to Real ZK

When moving to v0.2 (Pedersen commitments):

1. Keep function signatures unchanged (`create_amount_commitment`, `verify_amount_commitment`)
2. Swap SHA256 logic with Pedersen hash
3. Add range proof verification (separate function or integrated)
4. Update docs: remove "placeholder" language, add privacy claims
5. Run full regression test suite to ensure backward compatibility of verified commitments (if auditing is required)

---

## Additional Notes

### Soroban SDK Tips

- **Serialization**: Use `to_xdr()` for deterministic address bytes
- **Hashing**: `Env::crypto().sha256()` is the recommended hash
- **Bytes concat**: No built-in `+` operator; use helper functions to reconstruct
- **Testing**: Use `Address::generate(&env)` for test addresses

### References

- [Soroban SDK Documentation](https://docs.rs/soroban-sdk/)
- [X-Ray Privacy Specification](../docs/) (if available)
- [Commitment Schemes Overview](https://en.wikipedia.org/wiki/Commitment_scheme)
````
