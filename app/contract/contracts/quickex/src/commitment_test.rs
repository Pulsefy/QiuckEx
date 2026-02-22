//! Commitment Scheme Invariant Tests
//!
//! This module provides comprehensive property-based testing for the commitment scheme.
//! Tests validate the core invariants documented in commitment.rs.

use crate::{errors::QuickexError, QuickexContract, QuickexContractClient};
use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

extern crate std;

fn setup<'a>() -> (Env, QuickexContractClient<'a>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(QuickexContract, ());
    let client = QuickexContractClient::new(&env, &contract_id);
    (env, client)
}

// ============================================================================
// Invariant 1: Determinism - Same inputs → Same commitment
// ============================================================================

#[test]
fn test_commitment_deterministic_hashing() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount = 1_000_000i128;
    let salt = Bytes::from_slice(&env, b"deterministic_salt");

    let commitment1 = client.create_amount_commitment(&owner, &amount, &salt);
    let commitment2 = client.create_amount_commitment(&owner, &amount, &salt);

    assert_eq!(commitment1, commitment2);
}

#[test]
fn test_commitment_deterministic_multiple_calls() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount = 5_000i128;
    let salt = Bytes::from_slice(&env, b"repeat_test");

    let mut commitments = std::vec::Vec::new();
    for _ in 0..10 {
        commitments.push(client.create_amount_commitment(&owner, &amount, &salt));
    }

    for i in 1..commitments.len() {
        assert_eq!(commitments[0], commitments[i]);
    }
}

// ============================================================================
// Invariant 2: Collision Resistance - Different inputs → Different commitments
// ============================================================================

#[test]
fn test_commitment_different_amounts_different_hashes() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"amount_test");

    let amounts = [1i128, 100, 1_000, 10_000, 100_000, 1_000_000, i128::MAX];
    let mut commitments = std::vec::Vec::new();

    for &amount in &amounts {
        commitments.push(client.create_amount_commitment(&owner, &amount, &salt));
    }

    for i in 0..commitments.len() {
        for j in (i + 1)..commitments.len() {
            assert_ne!(commitments[i], commitments[j]);
        }
    }
}

#[test]
fn test_commitment_different_salts_different_hashes() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount = 1_000i128;

    let salts = [
        Bytes::from_slice(&env, b"salt1"),
        Bytes::from_slice(&env, b"salt2"),
        Bytes::from_slice(&env, b"different"),
        Bytes::from_slice(&env, b"x"),
        Bytes::from_slice(&env, b"very_long_salt_string_for_testing"),
    ];

    let mut commitments = std::vec::Vec::new();
    for salt in &salts {
        commitments.push(client.create_amount_commitment(&owner, &amount, salt));
    }

    for i in 0..commitments.len() {
        for j in (i + 1)..commitments.len() {
            assert_ne!(commitments[i], commitments[j]);
        }
    }
}

#[test]
fn test_commitment_multiple_owners_different_hashes() {
    let (env, client) = setup();
    let amount = 1_000i128;
    let salt = Bytes::from_slice(&env, b"owner_test");

    let owners = [
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
    ];

    let mut commitments = std::vec::Vec::new();
    for owner in &owners {
        commitments.push(client.create_amount_commitment(owner, &amount, &salt));
    }

    for i in 0..commitments.len() {
        for j in (i + 1)..commitments.len() {
            assert_ne!(commitments[i], commitments[j]);
        }
    }
}

// ============================================================================
// Invariant 3: Hiding Property - Commitment reveals nothing
// ============================================================================

#[test]
fn test_commitment_no_amount_leakage() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let salt = Bytes::from_slice(&env, b"hiding_test");

    let small_amount = 1i128;
    let large_amount = i128::MAX;

    let commitment_small = client.create_amount_commitment(&owner, &small_amount, &salt);
    let commitment_large = client.create_amount_commitment(&owner, &large_amount, &salt);

    // Both commitments are 32 bytes, no size correlation
    assert_eq!(commitment_small.len(), 32);
    assert_eq!(commitment_large.len(), 32);
    assert_ne!(commitment_small, commitment_large);
}

#[test]
fn test_commitment_empty_salt() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount = 1_000i128;
    let empty_salt = Bytes::new(&env);

    let commitment = client.create_amount_commitment(&owner, &amount, &empty_salt);
    assert_eq!(commitment.len(), 32);
}

// ============================================================================
// Invariant 4: Binding Property - Verification enforces correctness
// ============================================================================

#[test]
fn test_create_and_verify_commitment_success() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount = 5_000i128;
    let salt = Bytes::from_slice(&env, b"binding_test");

    let commitment = client.create_amount_commitment(&owner, &amount, &salt);
    let is_valid = client.verify_amount_commitment(&commitment, &owner, &amount, &salt);

    assert!(is_valid);
}

#[test]
fn test_verify_commitment_with_tampered_amount() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let original_amount = 1_000i128;
    let tampered_amount = 1_001i128;
    let salt = Bytes::from_slice(&env, b"tamper_amount");

    let commitment = client.create_amount_commitment(&owner, &original_amount, &salt);
    let is_valid = client.verify_amount_commitment(&commitment, &owner, &tampered_amount, &salt);

    assert!(!is_valid);
}

#[test]
fn test_verify_commitment_with_tampered_salt() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount = 1_000i128;
    let original_salt = Bytes::from_slice(&env, b"original");
    let tampered_salt = Bytes::from_slice(&env, b"tampered");

    let commitment = client.create_amount_commitment(&owner, &amount, &original_salt);
    let is_valid = client.verify_amount_commitment(&commitment, &owner, &amount, &tampered_salt);

    assert!(!is_valid);
}

#[test]
fn test_verify_commitment_with_different_owner() {
    let (env, client) = setup();
    let original_owner = Address::generate(&env);
    let different_owner = Address::generate(&env);
    let amount = 1_000i128;
    let salt = Bytes::from_slice(&env, b"owner_binding");

    let commitment = client.create_amount_commitment(&original_owner, &amount, &salt);
    let is_valid = client.verify_amount_commitment(&commitment, &different_owner, &amount, &salt);

    assert!(!is_valid);
}

// ============================================================================
// Security Constraints
// ============================================================================

#[test]
fn test_commitment_zero_amount() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount = 0i128;
    let salt = Bytes::from_slice(&env, b"zero_test");

    let commitment = client.create_amount_commitment(&owner, &amount, &salt);
    assert_eq!(commitment.len(), 32);
}

#[test]
fn test_commitment_negative_amount_rejected() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount = -1i128;
    let salt = Bytes::from_slice(&env, b"negative_test");

    let result = client.try_create_amount_commitment(&owner, &amount, &salt);
    assert_eq!(result, Err(Ok(QuickexError::InvalidAmount)));
}

#[test]
fn test_commitment_large_amount() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount = i128::MAX;
    let salt = Bytes::from_slice(&env, b"max_amount");

    let commitment = client.create_amount_commitment(&owner, &amount, &salt);
    assert_eq!(commitment.len(), 32);
}

#[test]
fn test_commitment_oversized_salt_rejected() {
    let (env, client) = setup();
    let owner = Address::generate(&env);
    let amount = 1_000i128;

    let mut large_salt = Bytes::new(&env);
    for _ in 0..1025 {
        large_salt.push_back(0xFF);
    }

    let result = client.try_create_amount_commitment(&owner, &amount, &large_salt);
    assert_eq!(result, Err(Ok(QuickexError::InvalidSalt)));
}

// ============================================================================
// Property-Based Tests (Pseudo-Random Generation)
// ============================================================================

#[test]
fn test_commitment_property_uniqueness_batch() {
    let (env, client) = setup();
    let owner = Address::generate(&env);

    let test_cases = [
        (1i128, b"salt_a" as &[u8]),
        (2, b"salt_b"),
        (100, b"salt_c"),
        (1_000, b"salt_a"),
        (1, b"salt_b"),
        (1_000_000, b"unique"),
        (999_999, b"unique"),
        (1_000_000, b"different"),
    ];

    let mut commitments = std::vec::Vec::new();
    for (amount, salt_bytes) in &test_cases {
        let salt = Bytes::from_slice(&env, salt_bytes);
        commitments.push((
            *amount,
            salt_bytes,
            client.create_amount_commitment(&owner, amount, &salt),
        ));
    }

    // Verify that only identical (amount, salt) pairs produce identical commitments
    for i in 0..commitments.len() {
        for j in (i + 1)..commitments.len() {
            let (amt_i, salt_i, comm_i) = &commitments[i];
            let (amt_j, salt_j, comm_j) = &commitments[j];

            if amt_i == amt_j && salt_i == salt_j {
                assert_eq!(comm_i, comm_j, "Same inputs must produce same commitment");
            } else {
                assert_ne!(
                    comm_i, comm_j,
                    "Different inputs must produce different commitments"
                );
            }
        }
    }
}

#[test]
fn test_commitment_property_verification_consistency() {
    let (env, client) = setup();

    let test_vectors = [
        (Address::generate(&env), 100i128, b"test1" as &[u8]),
        (Address::generate(&env), 500, b"test2"),
        (Address::generate(&env), 1_000_000, b"long_salt_string"),
        (Address::generate(&env), 0, b"zero"),
        (Address::generate(&env), i128::MAX - 1, b"near_max"),
    ];

    for (owner, amount, salt_bytes) in &test_vectors {
        let salt = Bytes::from_slice(&env, salt_bytes);
        let commitment = client.create_amount_commitment(owner, amount, &salt);

        // Correct verification must succeed
        assert!(client.verify_amount_commitment(&commitment, owner, amount, &salt));

        // Wrong amount must fail (only if we can safely add 1)
        if *amount < i128::MAX {
            let wrong_amount = amount + 1;
            assert!(!client.verify_amount_commitment(&commitment, owner, &wrong_amount, &salt));
        }

        // Wrong salt must fail
        let wrong_salt = Bytes::from_slice(&env, b"wrong");
        assert!(!client.verify_amount_commitment(&commitment, owner, amount, &wrong_salt));

        // Wrong owner must fail
        let wrong_owner = Address::generate(&env);
        assert!(!client.verify_amount_commitment(&commitment, &wrong_owner, amount, &salt));
    }
}
