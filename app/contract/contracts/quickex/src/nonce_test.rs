//! Tests for the nonce / replay-protection module.
//!
//! Covers:
//! - Happy path: fresh nonce within expiry window succeeds.
//! - Replay: same (signer, nonce) rejected with NonceAlreadyUsed.
//! - Expired: valid_until in the past rejected with SignatureExpired.
//! - Nonce gap: non-sequential nonces are independent (no ordering requirement).
//! - Domain prefix: includes contract address and network passphrase.

#[cfg(test)]
mod tests {
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Env,
    };

    use crate::{
        errors::QuickexError,
        nonce::{domain_prefix, is_nonce_used, verify_and_consume},
    };

    fn setup() -> (Env, soroban_sdk::Address) {
        let env = Env::default();
        env.mock_all_auths();
        // Set a known ledger timestamp so tests are deterministic.
        env.ledger().with_mut(|li| li.timestamp = 1_000_000);
        let signer = soroban_sdk::Address::generate(&env);
        (env, signer)
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn fresh_nonce_within_window_succeeds() {
        let (env, signer) = setup();
        let nonce = 1u64;
        let valid_until = 2_000_000u64; // well in the future

        let result = verify_and_consume(&env, &signer, nonce, valid_until);
        assert!(result.is_ok());
    }

    #[test]
    fn nonce_is_marked_used_after_consumption() {
        let (env, signer) = setup();
        let nonce = 42u64;
        let valid_until = 2_000_000u64;

        assert!(!is_nonce_used(&env, &signer, nonce));
        verify_and_consume(&env, &signer, nonce, valid_until).unwrap();
        assert!(is_nonce_used(&env, &signer, nonce));
    }

    // ── Replay protection ─────────────────────────────────────────────────────

    #[test]
    fn replay_same_nonce_fails_with_nonce_already_used() {
        let (env, signer) = setup();
        let nonce = 7u64;
        let valid_until = 2_000_000u64;

        // First use succeeds.
        verify_and_consume(&env, &signer, nonce, valid_until).unwrap();

        // Replay must fail deterministically.
        let result = verify_and_consume(&env, &signer, nonce, valid_until);
        assert_eq!(result, Err(QuickexError::NonceAlreadyUsed));
    }

    #[test]
    fn different_signers_same_nonce_are_independent() {
        let (env, signer_a) = setup();
        let signer_b = soroban_sdk::Address::generate(&env);
        let nonce = 1u64;
        let valid_until = 2_000_000u64;

        verify_and_consume(&env, &signer_a, nonce, valid_until).unwrap();
        // signer_b has not used nonce 1 yet — must succeed.
        let result = verify_and_consume(&env, &signer_b, nonce, valid_until);
        assert!(result.is_ok());
    }

    // ── Expiry enforcement ────────────────────────────────────────────────────

    #[test]
    fn expired_signature_fails_with_signature_expired() {
        let (env, signer) = setup();
        // valid_until is in the past relative to ledger timestamp (1_000_000).
        let valid_until = 999_999u64;

        let result = verify_and_consume(&env, &signer, 1, valid_until);
        assert_eq!(result, Err(QuickexError::SignatureExpired));
    }

    #[test]
    fn signature_at_exact_expiry_boundary_fails() {
        let (env, signer) = setup();
        // valid_until == current timestamp → expired (strict <).
        let valid_until = 1_000_000u64;

        let result = verify_and_consume(&env, &signer, 1, valid_until);
        assert_eq!(result, Err(QuickexError::SignatureExpired));
    }

    #[test]
    fn signature_one_second_before_expiry_succeeds() {
        let (env, signer) = setup();
        let valid_until = 1_000_001u64; // one second after current timestamp

        let result = verify_and_consume(&env, &signer, 1, valid_until);
        assert!(result.is_ok());
    }

    // ── Nonce gaps ────────────────────────────────────────────────────────────

    #[test]
    fn non_sequential_nonces_are_independent() {
        let (env, signer) = setup();
        let valid_until = 2_000_000u64;

        // Use nonce 100, skip 1-99.
        verify_and_consume(&env, &signer, 100, valid_until).unwrap();
        // Nonce 1 is still fresh.
        assert!(verify_and_consume(&env, &signer, 1, valid_until).is_ok());
        // Nonce 100 is consumed.
        assert_eq!(
            verify_and_consume(&env, &signer, 100, valid_until),
            Err(QuickexError::NonceAlreadyUsed)
        );
    }

    // ── Domain separation ─────────────────────────────────────────────────────

    #[test]
    fn domain_prefix_is_non_empty() {
        let (env, _) = setup();
        let prefix = domain_prefix(&env);
        assert!(prefix.len() > 0);
    }

    #[test]
    fn domain_prefix_differs_across_contract_instances() {
        // Two separate Env instances have different contract addresses.
        let env_a = Env::default();
        let env_b = Env::default();
        env_a.mock_all_auths();
        env_b.mock_all_auths();

        let prefix_a = domain_prefix(&env_a);
        let prefix_b = domain_prefix(&env_b);

        // Different contract deployments must produce different prefixes.
        assert_ne!(prefix_a, prefix_b);
    }
}
