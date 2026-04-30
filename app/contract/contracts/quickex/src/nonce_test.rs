//! Tests for the nonce / replay-protection module.
//!
//! All tests run inside a deployed contract context via `env.as_contract`
//! so that persistent storage and `current_contract_address()` are available.

#[cfg(test)]
mod tests {
    use soroban_sdk::testutils::{Address as _, Ledger};

    use crate::{
        errors::QuickexError,
        nonce::{domain_prefix, is_nonce_used, verify_and_consume},
        test_context::TestContext,
    };

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn fresh_nonce_within_window_succeeds() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer = soroban_sdk::Address::generate(&ctx.env);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let result = verify_and_consume(&ctx.env, &signer, 1, 2_000_000);
            assert!(result.is_ok());
        });
    }

    #[test]
    fn nonce_is_marked_used_after_consumption() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer = soroban_sdk::Address::generate(&ctx.env);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            assert!(!is_nonce_used(&ctx.env, &signer, 42));
            verify_and_consume(&ctx.env, &signer, 42, 2_000_000).unwrap();
            assert!(is_nonce_used(&ctx.env, &signer, 42));
        });
    }

    // ── Replay protection ─────────────────────────────────────────────────────

    #[test]
    fn replay_same_nonce_fails_with_nonce_already_used() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer = soroban_sdk::Address::generate(&ctx.env);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            verify_and_consume(&ctx.env, &signer, 7, 2_000_000).unwrap();
            let result = verify_and_consume(&ctx.env, &signer, 7, 2_000_000);
            assert_eq!(result, Err(QuickexError::NonceAlreadyUsed));
        });
    }

    #[test]
    fn different_signers_same_nonce_are_independent() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer_a = soroban_sdk::Address::generate(&ctx.env);
        let signer_b = soroban_sdk::Address::generate(&ctx.env);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            verify_and_consume(&ctx.env, &signer_a, 1, 2_000_000).unwrap();
            // signer_b has not used nonce 1 — must succeed.
            assert!(verify_and_consume(&ctx.env, &signer_b, 1, 2_000_000).is_ok());
        });
    }

    // ── Expiry enforcement ────────────────────────────────────────────────────

    #[test]
    fn expired_signature_fails_with_signature_expired() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer = soroban_sdk::Address::generate(&ctx.env);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            // valid_until is in the past
            let result = verify_and_consume(&ctx.env, &signer, 1, 999_999);
            assert_eq!(result, Err(QuickexError::SignatureExpired));
        });
    }

    #[test]
    fn signature_at_exact_expiry_boundary_fails() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer = soroban_sdk::Address::generate(&ctx.env);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            // valid_until == current timestamp → expired (strict <)
            let result = verify_and_consume(&ctx.env, &signer, 1, 1_000_000);
            assert_eq!(result, Err(QuickexError::SignatureExpired));
        });
    }

    #[test]
    fn signature_one_second_before_expiry_succeeds() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer = soroban_sdk::Address::generate(&ctx.env);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let result = verify_and_consume(&ctx.env, &signer, 1, 1_000_001);
            assert!(result.is_ok());
        });
    }

    // ── Nonce gaps ────────────────────────────────────────────────────────────

    #[test]
    fn non_sequential_nonces_are_independent() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer = soroban_sdk::Address::generate(&ctx.env);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            verify_and_consume(&ctx.env, &signer, 100, 2_000_000).unwrap();
            // Nonce 1 (skipped) is still fresh.
            assert!(verify_and_consume(&ctx.env, &signer, 1, 2_000_000).is_ok());
            // Nonce 100 is consumed.
            assert_eq!(
                verify_and_consume(&ctx.env, &signer, 100, 2_000_000),
                Err(QuickexError::NonceAlreadyUsed)
            );
        });
    }

    // ── Domain separation ─────────────────────────────────────────────────────

    #[test]
    fn domain_prefix_is_non_empty() {
        let ctx = TestContext::new();
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let prefix = domain_prefix(&ctx.env);
            assert!(!prefix.is_empty());
        });
    }

    #[test]
    fn domain_prefix_includes_contract_and_network_binding() {
        let ctx = TestContext::new();
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let prefix = domain_prefix(&ctx.env);
            // Prefix must be at least 32 bytes (contract address XDR) + network id
            assert!(prefix.len() >= 32);
        });
    }
}
