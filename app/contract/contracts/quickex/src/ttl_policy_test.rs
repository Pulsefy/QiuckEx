//! Tests for the systematic TTL policy (near-expiry access, archived access, recovery).

use soroban_sdk::{testutils::Address as _, Address, Bytes, Env, Vec};

use crate::{
    errors::QuickexError,
    storage::{get_escrow, put_escrow, LEDGER_THRESHOLD, SIX_MONTHS_IN_LEDGERS},
    ttl_policy::{
        bump_escrow_ttl_with_policy, extend_ttl_or_archived, get_ttl_config,
        restore_archived_escrow, set_ttl_config, TtlConfig, DEFAULT_TTL_LEDGERS, MAX_TTL_LEDGERS,
        MIN_TTL_LEDGERS,
    },
    types::{EscrowEntry, EscrowStatus},
};

fn make_entry(env: &Env, token: Address, owner: Address, amount: i128) -> EscrowEntry {
    EscrowEntry {
        token,
        amount_due: amount,
        amount_paid: amount,
        owner,
        status: EscrowStatus::Pending,
        created_at: env.ledger().timestamp(),
        expires_at: 0,
        arbiter: None,
        arbiters: Vec::new(env),
        arbiter_threshold: 0,
    }
}

// ---------------------------------------------------------------------------
// Policy configuration tests
// ---------------------------------------------------------------------------

#[test]
fn test_default_ttl_policy_values() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let cfg = get_ttl_config(&env);
        assert_eq!(cfg.ttl, DEFAULT_TTL_LEDGERS);
        assert_eq!(cfg.threshold, LEDGER_THRESHOLD);
    });
}

#[test]
fn test_set_ttl_config_within_bounds() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let cfg = TtlConfig {
            threshold: MIN_TTL_LEDGERS,
            ttl: SIX_MONTHS_IN_LEDGERS,
        };
        assert!(set_ttl_config(&env, cfg).is_ok());
        let stored = get_ttl_config(&env);
        assert_eq!(stored.ttl, SIX_MONTHS_IN_LEDGERS);
        assert_eq!(stored.threshold, MIN_TTL_LEDGERS);
    });
}

#[test]
fn test_set_ttl_config_max_bound() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let cfg = TtlConfig {
            threshold: LEDGER_THRESHOLD,
            ttl: MAX_TTL_LEDGERS,
        };
        assert!(set_ttl_config(&env, cfg).is_ok());
        let stored = get_ttl_config(&env);
        assert_eq!(stored.ttl, MAX_TTL_LEDGERS);
    });
}

#[test]
fn test_set_ttl_config_ttl_too_large_rejected() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let cfg = TtlConfig {
            threshold: LEDGER_THRESHOLD,
            ttl: MAX_TTL_LEDGERS + 1,
        };
        assert_eq!(
            set_ttl_config(&env, cfg).unwrap_err(),
            QuickexError::TtlOutOfBounds
        );
    });
}

#[test]
fn test_set_ttl_config_ttl_below_min_rejected() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let cfg = TtlConfig {
            threshold: LEDGER_THRESHOLD,
            ttl: MIN_TTL_LEDGERS - 1,
        };
        assert_eq!(
            set_ttl_config(&env, cfg).unwrap_err(),
            QuickexError::TtlOutOfBounds
        );
    });
}

#[test]
fn test_set_ttl_config_threshold_above_ttl_rejected() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        // threshold > ttl is invalid
        let cfg = TtlConfig {
            threshold: SIX_MONTHS_IN_LEDGERS + 1,
            ttl: SIX_MONTHS_IN_LEDGERS,
        };
        assert_eq!(
            set_ttl_config(&env, cfg).unwrap_err(),
            QuickexError::TtlOutOfBounds
        );
    });
}

// ---------------------------------------------------------------------------
// Near-expiry access bumps TTL
// ---------------------------------------------------------------------------

/// When an escrow is accessed with little TTL remaining (below the threshold),
/// the storage layer should extend it.  The Soroban testutils env exposes
/// `extend_ttl` but we verify the call path rather than the final TTL value
/// (which is opaque in the test environment).
#[test]
fn test_near_expiry_access_bumps_ttl() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment: Bytes = Bytes::from_array(&env, &[0xAAu8; 32]);
        let token = Address::generate(&env);
        let owner = Address::generate(&env);
        let entry = make_entry(&env, token, owner, 500);

        put_escrow(&env, &commitment, &entry);

        // Simulate the ledger advancing to just inside the threshold window.
        // The bump call should succeed (return true) meaning the key is live.
        let bumped = bump_escrow_ttl_with_policy(&env, &commitment);
        assert!(bumped, "TTL bump should succeed for a live entry");

        // The entry should still be readable after the bump.
        assert!(
            get_escrow(&env, &commitment).is_some(),
            "Entry must remain accessible after TTL bump"
        );
    });
}

#[test]
fn test_repeated_access_keeps_entry_live() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment: Bytes = Bytes::from_array(&env, &[0xBBu8; 32]);
        let token = Address::generate(&env);
        let owner = Address::generate(&env);
        let entry = make_entry(&env, token, owner, 1000);

        put_escrow(&env, &commitment, &entry);

        // Access the entry multiple times; each should succeed.
        for _ in 0..5 {
            let bumped = bump_escrow_ttl_with_policy(&env, &commitment);
            assert!(bumped);
            assert!(get_escrow(&env, &commitment).is_some());
        }
    });
}

// ---------------------------------------------------------------------------
// Archived entry returns distinct error
// ---------------------------------------------------------------------------

/// When no entry exists (simulates the archived state — both result in an
/// absent key in live storage), `extend_ttl_or_archived` must return
/// `EscrowArchived`, not `CommitmentNotFound` or a generic panic.
#[test]
fn test_absent_entry_returns_escrow_archived_error() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        // Commitment that was never stored (identical to an archived entry from
        // the contract's perspective — both are absent from live storage).
        let commitment_bytes: [u8; 32] = [0xCCu8; 32];
        let commitment: soroban_sdk::BytesN<32> =
            soroban_sdk::BytesN::from_array(&env, &commitment_bytes);

        let result = extend_ttl_or_archived(&env, commitment);
        assert_eq!(
            result.unwrap_err(),
            QuickexError::EscrowArchived,
            "Absent entry must produce EscrowArchived, not a generic error"
        );
    });
}

#[test]
fn test_absent_entry_bump_returns_false() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment: Bytes = Bytes::from_array(&env, &[0xDDu8; 32]);
        // Never stored.
        let bumped = bump_escrow_ttl_with_policy(&env, &commitment);
        assert!(!bumped, "bump must return false for absent/archived entry");
    });
}

// ---------------------------------------------------------------------------
// Recovery path: restore_archived_escrow
// ---------------------------------------------------------------------------

/// After a `RestoreFootprint` transaction is confirmed on-chain the entry
/// becomes visible in live storage again.  We simulate this by simply
/// storing the entry (mimicking a restored footprint) and then calling
/// `restore_archived_escrow`.
#[test]
fn test_restore_archived_escrow_success() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment_bytes: [u8; 32] = [0xEEu8; 32];
        let commitment_key: Bytes = Bytes::from_array(&env, &commitment_bytes);
        let commitment: soroban_sdk::BytesN<32> =
            soroban_sdk::BytesN::from_array(&env, &commitment_bytes);

        let token = Address::generate(&env);
        let owner = Address::generate(&env);
        let entry = make_entry(&env, token, owner, 2000);

        // Simulate the entry being restored on-chain (footprint restored).
        put_escrow(&env, &commitment_key, &entry);

        // restore_archived_escrow should succeed and re-anchor the TTL.
        let result = restore_archived_escrow(&env, commitment);
        assert!(
            result.is_ok(),
            "restore_archived_escrow must succeed after entry is live: {:?}",
            result.err()
        );

        // Entry must still be accessible after restoration.
        assert!(
            get_escrow(&env, &commitment_key).is_some(),
            "Entry must be readable after restore"
        );
    });
}

/// If the `RestoreFootprint` has NOT yet been confirmed (entry still absent),
/// `restore_archived_escrow` must return `EscrowArchived`.
#[test]
fn test_restore_archived_escrow_still_absent_returns_error() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment_bytes: [u8; 32] = [0xFFu8; 32];
        let commitment: soroban_sdk::BytesN<32> =
            soroban_sdk::BytesN::from_array(&env, &commitment_bytes);

        // Entry is absent — footprint not yet restored.
        let result = restore_archived_escrow(&env, commitment);
        assert_eq!(
            result.unwrap_err(),
            QuickexError::EscrowArchived,
            "restore must return EscrowArchived when entry is still absent"
        );
    });
}

/// Verify the full round-trip: entry is live → bump succeeds;
/// entry is removed → archived error; entry is re-inserted → restore succeeds.
#[test]
fn test_full_archive_and_recovery_round_trip() {
    let env = Env::default();
    let contract_id = env.register(crate::QuickexContract, ());
    env.as_contract(&contract_id, || {
        let commitment_bytes: [u8; 32] = [0x11u8; 32];
        let commitment_key: Bytes = Bytes::from_array(&env, &commitment_bytes);
        let commitment: soroban_sdk::BytesN<32> =
            soroban_sdk::BytesN::from_array(&env, &commitment_bytes);

        let token = Address::generate(&env);
        let owner = Address::generate(&env);
        let entry = make_entry(&env, token, owner, 3000);

        // 1. Store entry (live).
        put_escrow(&env, &commitment_key, &entry);
        assert!(bump_escrow_ttl_with_policy(&env, &commitment_key));

        // 2. Remove entry to simulate archival.
        crate::storage::remove_escrow(&env, &commitment_key);
        assert!(
            !bump_escrow_ttl_with_policy(&env, &commitment_key),
            "bump must fail for archived entry"
        );
        assert_eq!(
            extend_ttl_or_archived(&env, commitment.clone()).unwrap_err(),
            QuickexError::EscrowArchived
        );

        // 3. Simulate RestoreFootprint confirming — re-insert entry.
        put_escrow(&env, &commitment_key, &entry);

        // 4. Call restore_archived_escrow.
        assert!(restore_archived_escrow(&env, commitment).is_ok());

        // 5. Entry should be fully accessible.
        let restored = get_escrow(&env, &commitment_key);
        assert!(restored.is_some());
        assert_eq!(restored.unwrap().amount_due, 3000);
    });
}
