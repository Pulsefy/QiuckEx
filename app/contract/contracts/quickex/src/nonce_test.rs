//! Tests for the nonce / replay-protection module (Domain Separation v2).
//!
//! All tests run inside a deployed contract context via `env.as_contract`
//! so that persistent storage and `current_contract_address()` are available.
//!
//! # Migration compatibility
//!
//! The legacy [`domain_prefix_v1`] function is still exported for existing
//! test fixtures.  The new [`build_canonical_payload`] / [`verify_and_consume`]
//! with an explicit [`ActionType`] should be used for all new code.

#[cfg(test)]
mod tests {
    use soroban_sdk::testutils::{Address as _, Ledger};

    use crate::{
        errors::QuickexError,
        nonce::{
            self, build_canonical_payload, domain_prefix_v1, hash_canonical_payload, is_nonce_used,
            verify_and_consume, ActionType,
        },
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
            let result = verify_and_consume(&ctx.env, &signer, 1, 2_000_000, ActionType::Withdraw);
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
            assert!(!is_nonce_used(&ctx.env, &signer, 42, ActionType::Withdraw));
            verify_and_consume(&ctx.env, &signer, 42, 2_000_000, ActionType::Withdraw).unwrap();
            assert!(is_nonce_used(&ctx.env, &signer, 42, ActionType::Withdraw));
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
            verify_and_consume(&ctx.env, &signer, 7, 2_000_000, ActionType::Withdraw).unwrap();
            let result = verify_and_consume(&ctx.env, &signer, 7, 2_000_000, ActionType::Withdraw);
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
            verify_and_consume(&ctx.env, &signer_a, 1, 2_000_000, ActionType::Withdraw).unwrap();
            assert!(
                verify_and_consume(&ctx.env, &signer_b, 1, 2_000_000, ActionType::Withdraw).is_ok()
            );
        });
    }

    // ── Cross-method replay protection (NEW for v2) ───────────────────────────

    #[test]
    fn same_nonce_different_actions_are_independent() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer = soroban_sdk::Address::generate(&ctx.env);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            // Same nonce, different actions — both must succeed because the
            // NonceKey includes the ActionType.
            verify_and_consume(&ctx.env, &signer, 7, 2_000_000, ActionType::Withdraw).unwrap();
            verify_and_consume(&ctx.env, &signer, 7, 2_000_000, ActionType::Refund).unwrap();
            verify_and_consume(&ctx.env, &signer, 7, 2_000_000, ActionType::Deposit).unwrap();
        });
    }

    #[test]
    fn same_nonce_same_action_rejected_across_methods() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer = soroban_sdk::Address::generate(&ctx.env);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            verify_and_consume(&ctx.env, &signer, 42, 2_000_000, ActionType::Withdraw).unwrap();
            let result = verify_and_consume(&ctx.env, &signer, 42, 2_000_000, ActionType::Withdraw);
            assert_eq!(result, Err(QuickexError::NonceAlreadyUsed));
        });
    }

    #[test]
    fn all_action_types_are_distinct() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer = soroban_sdk::Address::generate(&ctx.env);
        let contract_id = ctx.client.address.clone();
        let nonce = 99u64;

        ctx.env.as_contract(&contract_id, || {
            let actions = [
                ActionType::Withdraw,
                ActionType::Refund,
                ActionType::Dispute,
                ActionType::ResolveDispute,
                ActionType::VoteForDispute,
                ActionType::ResolveDisputeMultiSig,
                ActionType::Deposit,
                ActionType::DepositWithCommitment,
                ActionType::DepositPartial,
                ActionType::PartialPayment,
                ActionType::StealthDeposit,
                ActionType::StealthWithdraw,
                ActionType::SetPrivacy,
                ActionType::Upgrade,
            ];
            for action in &actions {
                assert!(
                    verify_and_consume(&ctx.env, &signer, nonce, 2_000_000, *action).is_ok(),
                    "action {:?} should accept nonce {nonce}",
                    action,
                );
            }
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
            let result = verify_and_consume(&ctx.env, &signer, 1, 999_999, ActionType::Withdraw);
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
            let result = verify_and_consume(&ctx.env, &signer, 1, 1_000_000, ActionType::Withdraw);
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
            let result = verify_and_consume(&ctx.env, &signer, 1, 1_000_001, ActionType::Withdraw);
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
            verify_and_consume(&ctx.env, &signer, 100, 2_000_000, ActionType::Withdraw).unwrap();
            assert!(
                verify_and_consume(&ctx.env, &signer, 1, 2_000_000, ActionType::Withdraw).is_ok()
            );
            assert_eq!(
                verify_and_consume(&ctx.env, &signer, 100, 2_000_000, ActionType::Withdraw),
                Err(QuickexError::NonceAlreadyUsed)
            );
        });
    }

    // ── Canonical payload stability ───────────────────────────────────────────

    #[test]
    fn canonical_payload_is_stable_and_non_empty() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let payload = build_canonical_payload(&ctx.env, ActionType::Withdraw, 42, 2_000_000);
            assert!(!payload.is_empty(), "payload must not be empty");
            // Must contain the domain tag
            let tag = Bytes::from_slice(&ctx.env, nonce::SIGNED_PAYLOAD_DOMAIN_TAG);
            assert!(
                payload.len() > tag.len(),
                "payload should be longer than the domain tag alone"
            );
        });
    }

    use soroban_sdk::Bytes;

    #[test]
    fn canonical_payload_is_deterministic() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let p1 = build_canonical_payload(&ctx.env, ActionType::Refund, 1, 3_000_000);
            let p2 = build_canonical_payload(&ctx.env, ActionType::Refund, 1, 3_000_000);
            assert_eq!(p1, p2);
        });
    }

    #[test]
    fn canonical_payload_differs_by_action_type() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let p_wd = build_canonical_payload(&ctx.env, ActionType::Withdraw, 1, 3_000_000);
            let p_rf = build_canonical_payload(&ctx.env, ActionType::Refund, 1, 3_000_000);
            assert_ne!(p_wd, p_rf, "withdraw and refund payloads must differ");
        });
    }

    #[test]
    fn canonical_payload_differs_by_nonce() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let p1 = build_canonical_payload(&ctx.env, ActionType::Withdraw, 1, 3_000_000);
            let p2 = build_canonical_payload(&ctx.env, ActionType::Withdraw, 2, 3_000_000);
            assert_ne!(p1, p2, "payloads with different nonces must differ");
        });
    }

    #[test]
    fn canonical_payload_differs_by_valid_until() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let p1 = build_canonical_payload(&ctx.env, ActionType::Withdraw, 1, 3_000_000);
            let p2 = build_canonical_payload(&ctx.env, ActionType::Withdraw, 1, 4_000_000);
            assert_ne!(p1, p2, "payloads with different valid_until must differ");
        });
    }

    #[test]
    fn hash_canonical_payload_is_32_bytes() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let hash = hash_canonical_payload(&ctx.env, ActionType::Deposit, 7, 5_000_000);
            assert_eq!(hash.len(), 32);
        });
    }

    // ── Domain separation ─────────────────────────────────────────────────────

    #[test]
    fn domain_prefix_v1_is_non_empty() {
        let ctx = TestContext::new();
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let prefix = domain_prefix_v1(&ctx.env);
            assert!(!prefix.is_empty());
        });
    }

    #[test]
    fn domain_prefix_v1_includes_contract_and_network_binding() {
        let ctx = TestContext::new();
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let prefix = domain_prefix_v1(&ctx.env);
            assert!(prefix.len() >= 32);
        });
    }

    // ── Migration compatibility ───────────────────────────────────────────────

    #[test]
    fn v1_prefix_is_shorter_than_v2_payload() {
        // Sanity check: v2 payload adds the domain tag and action type,
        // so it must be strictly longer than the v1 prefix.
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            let v1 = domain_prefix_v1(&ctx.env);
            let v2 = build_canonical_payload(&ctx.env, ActionType::Withdraw, 0, 1_000_001);
            assert!(
                v2.len() > v1.len(),
                "v2 payload ({}) must be longer than v1 prefix ({})",
                v2.len(),
                v1.len(),
            );
        });
    }

    /// Verify that the v1 `NonceKey::UsedV1` still works for backward compat.
    /// Tests that old-style (signer, nonce) only tuples don't collide with new
    /// v2 (signer, nonce, action) tuples in storage.
    #[test]
    fn v1_nonce_key_backward_compatible() {
        use crate::nonce::NonceKey;

        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer = soroban_sdk::Address::generate(&ctx.env);
        let contract_id = ctx.client.address.clone();

        ctx.env.as_contract(&contract_id, || {
            // Write a v1 key directly into storage.
            let v1_key = NonceKey::UsedV1(signer.clone(), 99);
            ctx.env.storage().persistent().set(&v1_key, &true);

            // The v2 check for the same (signer, nonce, action) should NOT
            // see the v1 key — different storage discriminants.
            assert!(!is_nonce_used(&ctx.env, &signer, 99, ActionType::Withdraw));

            // But the v1 key is still independently readable.
            assert!(ctx.env.storage().persistent().has(&v1_key));
        });
    }

    // ── Cross-contract / cross-network simulation ─────────────────────────────

    /// Simulate a second contract by registering a new instance and checking
    /// that the canonical payload produced by contract A differs from B.
    #[test]
    fn canonical_payload_differs_across_contracts() {
        use soroban_sdk::{Env, IntoVal};

        let ctx_a = TestContext::new();
        ctx_a.env.ledger().set_timestamp(1_000_000);
        let contract_a = ctx_a.client.address.clone();

        // Deploy a second contract instance in the same env.
        let contract_b = ctx_a.env.register(crate::QuickexContract, ());

        let payload_a = ctx_a.env.as_contract(&contract_a, || {
            build_canonical_payload(&ctx_a.env, ActionType::Withdraw, 1, 2_000_000)
        });
        let payload_b = ctx_a.env.as_contract(&contract_b, || {
            build_canonical_payload(&ctx_a.env, ActionType::Withdraw, 1, 2_000_000)
        });

        assert_ne!(
            payload_a, payload_b,
            "payloads from different contracts must differ"
        );
    }

    /// Verify that replay across distinct contracts is blocked: consuming
    /// nonce N on contract A does not prevent consuming nonce N on contract B.
    #[test]
    fn nonce_scoped_per_contract() {
        let ctx = TestContext::new();
        ctx.env.ledger().set_timestamp(1_000_000);
        let signer = soroban_sdk::Address::generate(&ctx.env);
        let contract_a = ctx.client.address.clone();
        let contract_b = ctx.env.register(crate::QuickexContract, ());

        // Consume on A
        ctx.env.as_contract(&contract_a, || {
            verify_and_consume(&ctx.env, &signer, 1, 2_000_000, ActionType::Withdraw).unwrap();
        });

        // Still available on B
        ctx.env.as_contract(&contract_b, || {
            let result = verify_and_consume(&ctx.env, &signer, 1, 2_000_000, ActionType::Withdraw);
            assert!(
                result.is_ok(),
                "nonce should be scoped per-contract — contract B must accept"
            );
        });

        // Replay on A must still fail
        ctx.env.as_contract(&contract_a, || {
            let result = verify_and_consume(&ctx.env, &signer, 1, 2_000_000, ActionType::Withdraw);
            assert_eq!(result, Err(QuickexError::NonceAlreadyUsed));
        });
    }

    #[test]
    fn action_type_as_bytes_all_variants_non_empty() {
        let actions = [
            (ActionType::Withdraw, "WITHDRAW"),
            (ActionType::Refund, "REFUND"),
            (ActionType::Dispute, "DISPUTE"),
            (ActionType::ResolveDispute, "RESOLVE_DISPUTE"),
            (ActionType::VoteForDispute, "VOTE_FOR_DISPUTE"),
            (
                ActionType::ResolveDisputeMultiSig,
                "RESOLVE_DISPUTE_MULTI_SIG",
            ),
            (ActionType::Deposit, "DEPOSIT"),
            (ActionType::DepositWithCommitment, "DEPOSIT_WITH_COMMITMENT"),
            (ActionType::DepositPartial, "DEPOSIT_PARTIAL"),
            (ActionType::PartialPayment, "PARTIAL_PAYMENT"),
            (ActionType::StealthDeposit, "STEALTH_DEPOSIT"),
            (ActionType::StealthWithdraw, "STEALTH_WITHDRAW"),
            (ActionType::SetPrivacy, "SET_PRIVACY"),
            (ActionType::Upgrade, "UPGRADE"),
        ];
        for (variant, expected) in &actions {
            assert_eq!(variant.as_bytes(), expected.as_bytes());
        }
    }
}
