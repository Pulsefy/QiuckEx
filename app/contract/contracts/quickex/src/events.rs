use soroban_sdk::{contractevent, Address, Bytes, BytesN, Env};

/// Canonical event schema version.
///
/// Increment this constant whenever the event payload shape changes
/// (fields added, removed, or renamed). Indexers MUST check this field
/// before parsing any event payload so they can route to the correct
/// decoder for the schema version they understand.
///
/// History:
///   v1 – original schema (no version field)
///   v2 – added `schema_version` to every event payload
///   v3 – added deterministic `receipt_reference` to escrow lifecycle events
///        (SC-W7-07)
pub const EVENT_SCHEMA_VERSION: u32 = 3;

/// Testnet event topic namespace used as topic[0] for every QuickEx event.
#[allow(dead_code)]
pub const EVENT_TOPIC_ADMIN: &str = "TOPIC_ADMIN";
#[allow(dead_code)]
pub const EVENT_TOPIC_DISPUTE: &str = "TOPIC_DISPUTE";
#[allow(dead_code)]
pub const EVENT_TOPIC_ESCROW: &str = "TOPIC_ESCROW";
#[allow(dead_code)]
pub const EVENT_TOPIC_PRIVACY: &str = "TOPIC_PRIVACY";
#[allow(dead_code)]
pub const EVENT_TOPIC_STEALTH: &str = "TOPIC_STEALTH";
#[allow(dead_code)]
pub const EVENT_TOPIC_ORACLE: &str = "TOPIC_ORACLE";

/// Domain-separation tag for receipt reference derivation (SC-W7-07).
///
/// The tag keeps receipt references distinct from other SHA-256 digests in
/// the protocol (escrow ids, amount commitments, stealth addresses), so no
/// two schemes can collide under a chosen-input attack.
pub const RECEIPT_REFERENCE_DOMAIN_TAG: &[u8] = b"QUICKEX::RECEIPT_REF::v1";

/// Stable action labels used to derive deterministic receipt references.
pub const RECEIPT_REF_ACTION_DEPOSIT: &str = "deposit";
pub const RECEIPT_REF_ACTION_WITHDRAW: &str = "withdraw";
pub const RECEIPT_REF_ACTION_REFUND: &str = "refund";
pub const RECEIPT_REF_ACTION_REFUND_FINALIZED: &str = "refund_finalized";
pub const RECEIPT_REF_ACTION_FINALIZE: &str = "finalize";

/// Derive the deterministic receipt reference for an escrow action.
///
/// The reference is a SHA-256 digest of the canonical escrow id plus a
/// stable action label. It intentionally does NOT depend on ledger time,
/// balances, callers, or any other runtime state, so identical escrow
/// actions always yield the same reference and off-chain receipt generation
/// can key on it deterministically.
///
/// # Invariants
/// - Determinism: same `escrow_id` + `action` ⇒ same reference.
/// - Domain separation: different actions or escrows ⇒ different references
///   with negligible collision probability (SHA-256).
pub fn generate_receipt_reference(env: &Env, escrow_id: &BytesN<32>, action: &str) -> BytesN<32> {
    let mut payload = Bytes::new(env);
    let escrow_bytes: Bytes = escrow_id.clone().into();
    payload.append(&escrow_bytes);
    payload.append(&Bytes::from_slice(env, RECEIPT_REFERENCE_DOMAIN_TAG));
    payload.append(&Bytes::from_slice(env, action.as_bytes()));
    env.crypto().sha256(&payload).into()
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventSchema {
    pub name: &'static str,
    pub topics: &'static [&'static str],
    pub payload_keys: &'static [&'static str],
    pub schema_version: u32,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventCompatibility {
    pub name: &'static str,
    pub current_version: u32,
    pub compatible_versions: &'static [u32],
}

#[allow(dead_code)]
pub const EVENT_SCHEMAS: &[EventSchema] = &[
    EventSchema {
        name: "AdminChanged",
        topics: &[EVENT_TOPIC_ADMIN, "AdminChanged", "old_admin", "new_admin"],
        payload_keys: &["schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "AdminTransferProposed",
        topics: &[
            EVENT_TOPIC_ADMIN,
            "AdminTransferProposed",
            "current_admin",
            "proposed_admin",
        ],
        payload_keys: &["eligible_at", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "AdminTransferAccepted",
        topics: &[
            EVENT_TOPIC_ADMIN,
            "AdminTransferAccepted",
            "old_admin",
            "new_admin",
        ],
        payload_keys: &["schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "AdminTransferCancelled",
        topics: &[
            EVENT_TOPIC_ADMIN,
            "AdminTransferCancelled",
            "current_admin",
            "cancelled_proposed_admin",
        ],
        payload_keys: &["schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "ArbiterVoteCast",
        topics: &[
            EVENT_TOPIC_DISPUTE,
            "ArbiterVoteCast",
            "escrow_id",
            "arbiter",
        ],
        payload_keys: &[
            "resolve_for_owner",
            "schema_version",
            "threshold",
            "timestamp",
            "vote_count",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "ContractMigrated",
        topics: &[EVENT_TOPIC_ADMIN, "ContractMigrated", "admin"],
        payload_keys: &["from_version", "schema_version", "timestamp", "to_version"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "ContractInitialized",
        topics: &[EVENT_TOPIC_ADMIN, "ContractInitialized", "admin"],
        payload_keys: &[
            "contract_version",
            "event_schema_version",
            "paused",
            "schema_version",
            "timestamp",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "ContractPaused",
        topics: &[EVENT_TOPIC_ADMIN, "ContractPaused", "admin"],
        payload_keys: &["paused", "reason", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "PauseEnabled",
        topics: &[EVENT_TOPIC_ADMIN, "PauseEnabled", "admin"],
        payload_keys: &["flag", "is_global", "reason", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "PauseDisabled",
        topics: &[EVENT_TOPIC_ADMIN, "PauseDisabled", "admin"],
        payload_keys: &["flag", "is_global", "reason", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "PauseEnforced",
        topics: &[EVENT_TOPIC_ADMIN, "PauseEnforced", "caller"],
        payload_keys: &["action", "reason", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "ContractUpgraded",
        topics: &[
            EVENT_TOPIC_ADMIN,
            "ContractUpgraded",
            "new_wasm_hash",
            "admin",
        ],
        payload_keys: &["schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "UpgradeStarted",
        topics: &[EVENT_TOPIC_ADMIN, "UpgradeStarted", "admin"],
        payload_keys: &[
            "new_version",
            "old_version",
            "schema_version",
            "timestamp",
            "window_end",
            "window_start",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "UpgradeCompleted",
        topics: &[EVENT_TOPIC_ADMIN, "UpgradeCompleted", "admin"],
        payload_keys: &["new_version", "old_version", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "DisputeResolved",
        topics: &[
            EVENT_TOPIC_DISPUTE,
            "DisputeResolved",
            "escrow_id",
            "resolved_for_owner",
        ],
        payload_keys: &[
            "amount",
            "schema_version",
            "threshold",
            "timestamp",
            "total_votes",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "DisputeQuorumTimeout",
        topics: &[EVENT_TOPIC_DISPUTE, "DisputeQuorumTimeout", "escrow_id"],
        payload_keys: &[
            "amount",
            "deadline",
            "fresh_votes",
            "required_votes",
            "schema_version",
            "timestamp",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "EmergencyModeActivated",
        topics: &[EVENT_TOPIC_ADMIN, "EmergencyModeActivated", "admin"],
        payload_keys: &["schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "EphemeralKeyRegistered",
        topics: &[
            EVENT_TOPIC_STEALTH,
            "EphemeralKeyRegistered",
            "stealth_address",
            "eph_pub",
        ],
        payload_keys: &[
            "amount_due",
            "amount_paid",
            "expires_at",
            "receipt_reference",
            "schema_version",
            "timestamp",
            "token",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "EscrowDeposited",
        topics: &[EVENT_TOPIC_ESCROW, "EscrowDeposited", "escrow_id", "owner"],
        payload_keys: &[
            "amount_due",
            "amount_paid",
            "expires_at",
            "receipt_reference",
            "schema_version",
            "timestamp",
            "token",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "EscrowDisputed",
        topics: &[EVENT_TOPIC_ESCROW, "EscrowDisputed", "escrow_id", "arbiter"],
        payload_keys: &["schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "EscrowFinalized",
        topics: &[EVENT_TOPIC_ESCROW, "EscrowFinalized", "escrow_id", "owner"],
        payload_keys: &[
            "receipt_reference",
            "schema_version",
            "timestamp",
            "token",
            "total_amount",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "EscrowRefunded",
        topics: &[EVENT_TOPIC_ESCROW, "EscrowRefunded", "escrow_id", "owner"],
        payload_keys: &[
            "amount",
            "receipt_reference",
            "schema_version",
            "timestamp",
            "token",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "RefundFinalized",
        topics: &[EVENT_TOPIC_ESCROW, "RefundFinalized", "escrow_id", "owner"],
        payload_keys: &[
            "amount",
            "expires_at",
            "receipt_reference",
            "schema_version",
            "timestamp",
            "token",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "EscrowWithdrawn",
        topics: &[EVENT_TOPIC_ESCROW, "EscrowWithdrawn", "escrow_id", "owner"],
        payload_keys: &[
            "amount",
            "fee",
            "receipt_reference",
            "schema_version",
            "timestamp",
            "token",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "FeeCollectorRotated",
        topics: &[EVENT_TOPIC_ADMIN, "FeeCollectorRotated", "new_collector"],
        payload_keys: &["rotation_index", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "FeeConfigChanged",
        topics: &[EVENT_TOPIC_ADMIN, "FeeConfigChanged"],
        payload_keys: &["fee_bps", "old_fee_bps", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "FeeWithdrawn",
        topics: &[EVENT_TOPIC_ADMIN, "FeeWithdrawn", "token"],
        payload_keys: &[
            "actor",
            "amount",
            "recipient",
            "remaining_balance",
            "schema_version",
            "timestamp",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "PartialPayment",
        topics: &[EVENT_TOPIC_ESCROW, "PartialPayment", "escrow_id", "payer"],
        payload_keys: &[
            "amount_due",
            "amount_paid",
            "payment_amount",
            "schema_version",
            "timestamp",
            "token",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "PerAssetFeeSet",
        topics: &[EVENT_TOPIC_ADMIN, "PerAssetFeeSet", "token"],
        payload_keys: &[
            "arbiter_bps",
            "fee_bps",
            "old_arbiter_bps",
            "old_fee_bps",
            "schema_version",
            "timestamp",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "PlatformWalletChanged",
        topics: &[EVENT_TOPIC_ADMIN, "PlatformWalletChanged", "wallet"],
        payload_keys: &["schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "PrivacyToggled",
        topics: &[EVENT_TOPIC_PRIVACY, "PrivacyToggled", "owner"],
        payload_keys: &["enabled", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "StealthWithdrawn",
        topics: &[
            EVENT_TOPIC_STEALTH,
            "StealthWithdrawn",
            "stealth_address",
            "recipient",
        ],
        payload_keys: &["amount", "schema_version", "timestamp", "token"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "OraclePriceUpdated",
        topics: &[EVENT_TOPIC_ORACLE, "OraclePriceUpdated"],
        payload_keys: &["price_micros", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "HookAllowlistChanged",
        topics: &[EVENT_TOPIC_ADMIN, "HookAllowlistChanged", "hook_contract"],
        payload_keys: &["allowed", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "OracleSourceRegistered",
        topics: &[EVENT_TOPIC_ORACLE, "OracleSourceRegistered", "source"],
        payload_keys: &["schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "OracleSourceUnregistered",
        topics: &[EVENT_TOPIC_ORACLE, "OracleSourceUnregistered", "source"],
        payload_keys: &["schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "OracleSourcePriceRecorded",
        topics: &[EVENT_TOPIC_ORACLE, "OracleSourcePriceRecorded", "source"],
        payload_keys: &["price_micros", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "OracleSourceExcluded",
        topics: &[EVENT_TOPIC_ORACLE, "OracleSourceExcluded", "source"],
        payload_keys: &[
            "deviation_bps",
            "median_price_micros",
            "price_micros",
            "schema_version",
            "timestamp",
        ],
        schema_version: EVENT_SCHEMA_VERSION,
    },
];

#[allow(dead_code)]
pub const EVENT_COMPATIBILITY: &[EventCompatibility] = &[
    EventCompatibility {
        name: "AdminChanged",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[1, EVENT_SCHEMA_VERSION],
    },
    EventCompatibility {
        name: "EscrowDeposited",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[1, 2, EVENT_SCHEMA_VERSION],
    },
    EventCompatibility {
        name: "EscrowRefunded",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[1, 2, EVENT_SCHEMA_VERSION],
    },
    EventCompatibility {
        name: "EscrowWithdrawn",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[1, 2, EVENT_SCHEMA_VERSION],
    },
    EventCompatibility {
        name: "EscrowFinalized",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[2, EVENT_SCHEMA_VERSION],
    },
    EventCompatibility {
        name: "RefundFinalized",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[2, EVENT_SCHEMA_VERSION],
    },
    EventCompatibility {
        name: "PrivacyToggled",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[1, EVENT_SCHEMA_VERSION],
    },
    EventCompatibility {
        name: "PauseFlagsChanged",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[EVENT_SCHEMA_VERSION],
    },
];

#[contractevent(topics = ["TOPIC_ADMIN", "EmergencyModeActivated"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmergencyModeActivatedEvent {
    #[topic]
    pub admin: Address,
    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_emergency_mode_activated(env: &Env, admin: Address) {
    EmergencyModeActivatedEvent {
        admin,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_PRIVACY", "PrivacyToggled"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyToggledEvent {
    #[topic]
    pub owner: Address,

    pub schema_version: u32,
    pub enabled: bool,
    pub timestamp: u64,
}

#[contractevent(topics = ["TOPIC_ESCROW", "EscrowWithdrawn"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowWithdrawnEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub owner: Address,

    pub schema_version: u32,
    pub token: Address,
    pub amount: i128,
    pub fee: i128,
    pub timestamp: u64,
    pub receipt_reference: BytesN<32>,
}

#[contractevent(topics = ["TOPIC_ESCROW", "EscrowDeposited"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowDepositedEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub owner: Address,

    pub schema_version: u32,
    pub token: Address,
    pub amount_due: i128,
    pub amount_paid: i128,
    pub expires_at: u64,
    pub timestamp: u64,
    pub receipt_reference: BytesN<32>,
}

pub(crate) fn publish_privacy_toggled(env: &Env, owner: Address, enabled: bool) {
    PrivacyToggledEvent {
        owner,
        schema_version: EVENT_SCHEMA_VERSION,
        enabled,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[allow(dead_code)]
#[contractevent(topics = ["TOPIC_ADMIN", "ContractInitialized"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractInitializedEvent {
    #[topic]
    pub admin: Address,

    pub schema_version: u32,
    pub contract_version: u32,
    pub event_schema_version: u32,
    pub paused: bool,
    pub timestamp: u64,
}

#[allow(dead_code)]
pub(crate) fn publish_contract_initialized(
    env: &Env,
    admin: Address,
    contract_version: u32,
    event_schema_version: u32,
    paused: bool,
) {
    ContractInitializedEvent {
        admin,
        schema_version: EVENT_SCHEMA_VERSION,
        contract_version,
        event_schema_version,
        paused,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[allow(dead_code)]
#[contractevent(topics = ["TOPIC_ADMIN", "ContractPaused"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractPausedEvent {
    #[topic]
    pub admin: Address,

    pub schema_version: u32,
    pub paused: bool,
    pub reason: u32,
    pub timestamp: u64,
}

#[allow(dead_code)]
pub(crate) fn publish_contract_paused(env: &Env, admin: Address, paused: bool, reason: u32) {
    ContractPausedEvent {
        admin,
        schema_version: EVENT_SCHEMA_VERSION,
        paused,
        reason,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "PauseFlagsChanged"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseEnabledEvent {
    #[topic]
    pub admin: Address,
    pub schema_version: u32,
    pub is_global: bool,
    pub flags: u64,
    pub reason: u32,
    pub timestamp: u64,
}

#[contractevent(topics = ["TOPIC_ADMIN", "PauseFlagsChanged"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseDisabledEvent {
    #[topic]
    pub admin: Address,
    pub schema_version: u32,
    pub is_global: bool,
    pub flags: u64,
    pub reason: u32,
    pub timestamp: u64,
}

#[contractevent(topics = ["TOPIC_ADMIN", "PauseEnforced"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseEnforcedEvent {
    #[topic]
    pub caller: Option<Address>,
    pub schema_version: u32,
    pub action: soroban_sdk::Symbol,
    pub reason: u32,
    pub timestamp: u64,
}

#[allow(dead_code)]
pub(crate) fn publish_pause_enabled(
    env: &Env,
    admin: Address,
    is_global: bool,
    flag: u64,
    reason: u32,
) {
    PauseEnabledEvent {
        admin,
        schema_version: EVENT_SCHEMA_VERSION,
        is_global,
        flags: flag,
        reason,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[allow(dead_code)]
pub(crate) fn publish_pause_disabled(
    env: &Env,
    admin: Address,
    is_global: bool,
    flag: u64,
    reason: u32,
) {
    PauseDisabledEvent {
        admin,
        schema_version: EVENT_SCHEMA_VERSION,
        is_global,
        flags: flag,
        reason,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[allow(dead_code)]
pub(crate) fn publish_pause_enforced(
    env: &Env,
    caller: Option<Address>,
    action: soroban_sdk::Symbol,
    reason: u32,
) {
    PauseEnforcedEvent {
        caller,
        schema_version: EVENT_SCHEMA_VERSION,
        action,
        reason,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[allow(dead_code)]
#[contractevent(topics = ["TOPIC_ADMIN", "AdminChanged"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChangedEvent {
    #[topic]
    pub old_admin: Address,

    #[topic]
    pub new_admin: Address,

    pub schema_version: u32,
    pub timestamp: u64,
}

#[allow(dead_code)]
pub(crate) fn publish_admin_changed(env: &Env, old_admin: Address, new_admin: Address) {
    AdminChangedEvent {
        old_admin,
        new_admin,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

// ---- Timelocked admin transfer events (Issue #870) ----

#[contractevent(topics = ["TOPIC_ADMIN", "AdminTransferProposed"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferProposedEvent {
    #[topic]
    pub current_admin: Address,

    #[topic]
    pub proposed_admin: Address,

    pub eligible_at: u64,
    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_admin_transfer_proposed(
    env: &Env,
    current_admin: Address,
    proposed_admin: Address,
    eligible_at: u64,
) {
    AdminTransferProposedEvent {
        current_admin,
        proposed_admin,
        eligible_at,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "AdminTransferAccepted"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferAcceptedEvent {
    #[topic]
    pub old_admin: Address,

    #[topic]
    pub new_admin: Address,

    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_admin_transfer_accepted(env: &Env, old_admin: Address, new_admin: Address) {
    AdminTransferAcceptedEvent {
        old_admin,
        new_admin,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "AdminTransferCancelled"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferCancelledEvent {
    #[topic]
    pub current_admin: Address,

    #[topic]
    pub cancelled_proposed_admin: Address,

    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_admin_transfer_cancelled(
    env: &Env,
    current_admin: Address,
    cancelled_proposed_admin: Address,
) {
    AdminTransferCancelledEvent {
        current_admin,
        cancelled_proposed_admin,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "ContractUpgraded"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractUpgradedEvent {
    #[topic]
    pub new_wasm_hash: BytesN<32>,

    #[topic]
    pub admin: Address,

    pub schema_version: u32,
    pub timestamp: u64,
}

#[contractevent(topics = ["TOPIC_ADMIN", "UpgradeStarted"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeStartedEvent {
    #[topic]
    pub admin: Address,

    pub schema_version: u32,
    pub old_version: u32,
    pub new_version: u32,
    pub window_start: u64,
    pub window_end: u64,
    pub timestamp: u64,
}

#[contractevent(topics = ["TOPIC_ADMIN", "UpgradeCompleted"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeCompletedEvent {
    #[topic]
    pub admin: Address,

    pub schema_version: u32,
    pub old_version: u32,
    pub new_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_contract_upgraded(env: &Env, new_wasm_hash: BytesN<32>, admin: &Address) {
    ContractUpgradedEvent {
        new_wasm_hash,
        admin: admin.clone(),
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

pub(crate) fn publish_upgrade_started(
    env: &Env,
    admin: &Address,
    old_version: u32,
    new_version: u32,
    window_start: u64,
    window_end: u64,
) {
    UpgradeStartedEvent {
        admin: admin.clone(),
        schema_version: EVENT_SCHEMA_VERSION,
        old_version,
        new_version,
        window_start,
        window_end,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

pub(crate) fn publish_upgrade_completed(
    env: &Env,
    admin: &Address,
    old_version: u32,
    new_version: u32,
) {
    UpgradeCompletedEvent {
        admin: admin.clone(),
        schema_version: EVENT_SCHEMA_VERSION,
        old_version,
        new_version,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "ContractMigrated"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractMigratedEvent {
    #[topic]
    pub admin: Address,

    pub schema_version: u32,
    pub from_version: u32,
    pub to_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_contract_migrated(
    env: &Env,
    admin: &Address,
    from_version: u32,
    to_version: u32,
) {
    ContractMigratedEvent {
        admin: admin.clone(),
        schema_version: EVENT_SCHEMA_VERSION,
        from_version,
        to_version,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

pub(crate) fn publish_escrow_withdrawn(
    env: &Env,
    commitment: BytesN<32>,
    owner: Address,
    token: Address,
    amount: i128,
    fee: i128,
) {
    let receipt_reference =
        generate_receipt_reference(env, &commitment, RECEIPT_REF_ACTION_WITHDRAW);
    EscrowWithdrawnEvent {
        escrow_id: commitment,
        owner,
        schema_version: EVENT_SCHEMA_VERSION,
        token,
        amount,
        fee,
        timestamp: env.ledger().timestamp(),
        receipt_reference,
    }
    .publish(env);
}

pub(crate) fn publish_escrow_deposited(
    env: &Env,
    commitment: BytesN<32>,
    owner: Address,
    token: Address,
    amount_due: i128,
    amount_paid: i128,
    expires_at: u64,
) {
    let receipt_reference =
        generate_receipt_reference(env, &commitment, RECEIPT_REF_ACTION_DEPOSIT);
    EscrowDepositedEvent {
        escrow_id: commitment,
        owner,
        schema_version: EVENT_SCHEMA_VERSION,
        token,
        amount_due,
        amount_paid,
        expires_at,
        timestamp: env.ledger().timestamp(),
        receipt_reference,
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ESCROW", "EscrowRefunded"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowRefundedEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub owner: Address,

    pub schema_version: u32,
    pub token: Address,
    pub amount: i128,
    pub timestamp: u64,
    pub receipt_reference: BytesN<32>,
}

#[contractevent(topics = ["TOPIC_ESCROW", "RefundFinalized"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundFinalizedEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub owner: Address,

    pub schema_version: u32,
    pub token: Address,
    pub amount: i128,
    pub expires_at: u64,
    pub timestamp: u64,
    pub receipt_reference: BytesN<32>,
}

#[contractevent(topics = ["TOPIC_ESCROW", "PartialPayment"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialPaymentEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub payer: Address,

    pub schema_version: u32,
    pub token: Address,
    pub payment_amount: i128,
    pub amount_paid: i128,
    pub amount_due: i128,
    pub timestamp: u64,
}

#[contractevent(topics = ["TOPIC_ESCROW", "EscrowFinalized"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowFinalizedEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub owner: Address,

    pub schema_version: u32,
    pub token: Address,
    pub total_amount: i128,
    pub timestamp: u64,
    pub receipt_reference: BytesN<32>,
}

#[contractevent(topics = ["TOPIC_ESCROW", "EscrowDisputed"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowDisputedEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub arbiter: Address,

    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_escrow_disputed(env: &Env, commitment: BytesN<32>, arbiter: Address) {
    EscrowDisputedEvent {
        escrow_id: commitment,
        arbiter,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

pub(crate) fn publish_escrow_refunded(
    env: &Env,
    owner: Address,
    commitment: BytesN<32>,
    token: Address,
    amount: i128,
) {
    let receipt_reference = generate_receipt_reference(env, &commitment, RECEIPT_REF_ACTION_REFUND);
    EscrowRefundedEvent {
        escrow_id: commitment,
        owner,
        schema_version: EVENT_SCHEMA_VERSION,
        token,
        amount,
        timestamp: env.ledger().timestamp(),
        receipt_reference,
    }
    .publish(env);
}

pub(crate) fn publish_refund_finalized(
    env: &Env,
    commitment: BytesN<32>,
    owner: Address,
    token: Address,
    amount: i128,
    expires_at: u64,
) {
    let receipt_reference =
        generate_receipt_reference(env, &commitment, RECEIPT_REF_ACTION_REFUND_FINALIZED);
    RefundFinalizedEvent {
        escrow_id: commitment,
        owner,
        schema_version: EVENT_SCHEMA_VERSION,
        token,
        amount,
        expires_at,
        timestamp: env.ledger().timestamp(),
        receipt_reference,
    }
    .publish(env);
}

pub(crate) fn publish_partial_payment(
    env: &Env,
    commitment: BytesN<32>,
    payer: Address,
    token: Address,
    payment_amount: i128,
    amount_paid: i128,
    amount_due: i128,
) {
    PartialPaymentEvent {
        escrow_id: commitment,
        payer,
        schema_version: EVENT_SCHEMA_VERSION,
        token,
        payment_amount,
        amount_paid,
        amount_due,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

pub(crate) fn publish_escrow_finalized(
    env: &Env,
    commitment: BytesN<32>,
    owner: Address,
    token: Address,
    total_amount: i128,
) {
    let receipt_reference =
        generate_receipt_reference(env, &commitment, RECEIPT_REF_ACTION_FINALIZE);
    EscrowFinalizedEvent {
        escrow_id: commitment,
        owner,
        schema_version: EVENT_SCHEMA_VERSION,
        token,
        total_amount,
        timestamp: env.ledger().timestamp(),
        receipt_reference,
    }
    .publish(env);
}

// ---------------------------------------------------------------------------
// Stealth address events (Privacy v2 – Issue #157)
// ---------------------------------------------------------------------------

#[contractevent(topics = ["TOPIC_STEALTH", "EphemeralKeyRegistered"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EphemeralKeyRegisteredEvent {
    /// One-time stealth address (indexed for scanning).
    #[topic]
    pub stealth_address: BytesN<32>,

    /// Sender's ephemeral public key (indexed so recipient can scan).
    #[topic]
    pub eph_pub: BytesN<32>,

    pub schema_version: u32,
    pub token: Address,
    pub amount_due: i128,
    pub amount_paid: i128,
    pub expires_at: u64,
    pub timestamp: u64,
}

pub(crate) fn publish_ephemeral_key_registered(
    env: &Env,
    stealth_address: BytesN<32>,
    eph_pub: BytesN<32>,
    token: Address,
    amount_due: i128,
    amount_paid: i128,
    expires_at: u64,
) {
    EphemeralKeyRegisteredEvent {
        stealth_address,
        eph_pub,
        schema_version: EVENT_SCHEMA_VERSION,
        token,
        amount_due,
        amount_paid,
        expires_at,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_STEALTH", "StealthWithdrawn"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StealthWithdrawnEvent {
    /// One-time stealth address (indexed).
    #[topic]
    pub stealth_address: BytesN<32>,

    /// Recipient's real address – only revealed at withdrawal time.
    #[topic]
    pub recipient: Address,

    pub schema_version: u32,
    pub token: Address,
    pub amount: i128,
    pub timestamp: u64,
}

pub(crate) fn publish_stealth_withdrawn(
    env: &Env,
    stealth_address: BytesN<32>,
    recipient: Address,
    token: Address,
    amount: i128,
) {
    StealthWithdrawnEvent {
        stealth_address,
        recipient,
        schema_version: EVENT_SCHEMA_VERSION,
        token,
        amount,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "FeeConfigChanged"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeConfigChangedEvent {
    pub old_fee_bps: u32,
    pub fee_bps: u32,
    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_fee_config_changed(env: &Env, old_fee_bps: u32, fee_bps: u32) {
    FeeConfigChangedEvent {
        old_fee_bps,
        fee_bps,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "PlatformWalletChanged"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformWalletChangedEvent {
    #[topic]
    pub wallet: Address,
    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_platform_wallet_changed(env: &Env, wallet: Address) {
    PlatformWalletChangedEvent {
        wallet,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

// ---------------------------------------------------------------------------
// Multi-sig arbiter events
// ---------------------------------------------------------------------------

#[contractevent(topics = ["TOPIC_DISPUTE", "ArbiterVoteCast"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArbiterVoteCastEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub arbiter: Address,

    pub schema_version: u32,
    pub resolve_for_owner: bool,
    pub vote_count: u32,
    pub threshold: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_arbiter_vote_cast(
    env: &Env,
    commitment: BytesN<32>,
    arbiter: Address,
    resolve_for_owner: bool,
    vote_count: u32,
    threshold: u32,
) {
    ArbiterVoteCastEvent {
        escrow_id: commitment,
        arbiter,
        schema_version: EVENT_SCHEMA_VERSION,
        resolve_for_owner,
        vote_count,
        threshold,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_DISPUTE", "DisputeResolved"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisputeResolvedEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub resolved_for_owner: bool,

    pub schema_version: u32,
    pub total_votes: u32,
    pub threshold: u32,
    pub amount: i128,
    pub timestamp: u64,
}

pub(crate) fn publish_dispute_resolved(
    env: &Env,
    commitment: BytesN<32>,
    resolved_for_owner: bool,
    total_votes: u32,
    threshold: u32,
    amount: i128,
) {
    DisputeResolvedEvent {
        escrow_id: commitment,
        resolved_for_owner,
        schema_version: EVENT_SCHEMA_VERSION,
        total_votes,
        threshold,
        amount,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

/// Emitted when a multi-sig dispute is resolved via the quorum-timeout
/// fallback (Issue #865 / SC-W8-04) rather than a genuine majority vote —
/// distinguishable from [`DisputeResolvedEvent`] for indexers that need to
/// tell the two resolution paths apart.
#[contractevent(topics = ["TOPIC_DISPUTE", "DisputeQuorumTimeout"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisputeQuorumTimeoutEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    pub schema_version: u32,
    pub fresh_votes: u32,
    pub required_votes: u32,
    pub deadline: u64,
    pub amount: i128,
    pub timestamp: u64,
}

pub(crate) fn publish_dispute_quorum_timeout(
    env: &Env,
    commitment: BytesN<32>,
    fresh_votes: u32,
    required_votes: u32,
    deadline: u64,
    amount: i128,
) {
    DisputeQuorumTimeoutEvent {
        escrow_id: commitment,
        schema_version: EVENT_SCHEMA_VERSION,
        fresh_votes,
        required_votes,
        deadline,
        amount,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

// ---- Fee Router v2 events (Issue #305) -----

#[contractevent(topics = ["TOPIC_ADMIN", "FeeCollectorRotated"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeCollectorRotatedEvent {
    #[topic]
    pub new_collector: Address,
    pub rotation_index: u32,
    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_fee_collector_rotated(
    env: &Env,
    new_collector: Address,
    rotation_index: u32,
) {
    FeeCollectorRotatedEvent {
        new_collector,
        rotation_index,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

/// Emitted when accrued protocol fees are withdrawn from the treasury
/// (Issue #866 / SC-W8-05).
#[contractevent(topics = ["TOPIC_ADMIN", "FeeWithdrawn"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeWithdrawnEvent {
    #[topic]
    pub token: Address,
    pub actor: Address,
    pub amount: i128,
    pub recipient: Address,
    pub remaining_balance: i128,
    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_fee_withdrawn(
    env: &Env,
    token: Address,
    actor: Address,
    amount: i128,
    recipient: Address,
    remaining_balance: i128,
) {
    FeeWithdrawnEvent {
        token,
        actor,
        amount,
        recipient,
        remaining_balance,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "PerAssetFeeSet"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerAssetFeeSetEvent {
    #[topic]
    pub token: Address,
    pub old_fee_bps: u32,
    pub old_arbiter_bps: u32,
    pub fee_bps: u32,
    pub arbiter_bps: u32,
    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_per_asset_fee_set(
    env: &Env,
    token: Address,
    old_fee_bps: u32,
    old_arbiter_bps: u32,
    fee_bps: u32,
    arbiter_bps: u32,
) {
    PerAssetFeeSetEvent {
        token,
        old_fee_bps,
        old_arbiter_bps,
        fee_bps,
        arbiter_bps,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

// ---- Oracle price events (Issue #666) ----

#[contractevent(topics = ["TOPIC_ORACLE", "OraclePriceUpdated"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OraclePriceUpdatedEvent {
    pub schema_version: u32,
    pub price_micros: i128,
    pub timestamp: u64,
}

pub(crate) fn publish_oracle_price_updated(env: &Env, price_micros: i128, recorded_at: u64) {
    OraclePriceUpdatedEvent {
        schema_version: EVENT_SCHEMA_VERSION,
        price_micros,
        timestamp: recorded_at,
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "HookAllowlistChanged"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookAllowlistChangedEvent {
    #[topic]
    pub hook_contract: Address,

    pub schema_version: u32,
    pub allowed: bool,
    pub timestamp: u64,
}

pub(crate) fn publish_hook_allowlist_changed(env: &Env, hook_contract: Address, allowed: bool) {
    HookAllowlistChangedEvent {
        hook_contract,
        schema_version: EVENT_SCHEMA_VERSION,
        allowed,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

// ---- Multi-source oracle aggregation events (SC-W8-06 / Issue #867) ----

#[contractevent(topics = ["TOPIC_ORACLE", "OracleSourceRegistered"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleSourceRegisteredEvent {
    #[topic]
    pub source: Address,

    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_oracle_source_registered(env: &Env, source: Address) {
    OracleSourceRegisteredEvent {
        source,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ORACLE", "OracleSourceUnregistered"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleSourceUnregisteredEvent {
    #[topic]
    pub source: Address,

    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_oracle_source_unregistered(env: &Env, source: Address) {
    OracleSourceUnregisteredEvent {
        source,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ORACLE", "OracleSourcePriceRecorded"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleSourcePriceRecordedEvent {
    #[topic]
    pub source: Address,

    pub schema_version: u32,
    pub price_micros: i128,
    pub timestamp: u64,
}

pub(crate) fn publish_oracle_source_price_recorded(
    env: &Env,
    source: Address,
    price_micros: i128,
    recorded_at: u64,
) {
    OracleSourcePriceRecordedEvent {
        source,
        schema_version: EVENT_SCHEMA_VERSION,
        price_micros,
        timestamp: recorded_at,
    }
    .publish(env);
}

/// Emitted when [`crate::oracle::fetch_aggregated_price`] excludes a source
/// because its price deviates from the median by more than the configured
/// tolerance — the observability hook required by SC-W8-06's outlier
/// exclusion requirement.
#[contractevent(topics = ["TOPIC_ORACLE", "OracleSourceExcluded"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleSourceExcludedEvent {
    #[topic]
    pub source: Address,

    pub schema_version: u32,
    pub price_micros: i128,
    pub median_price_micros: i128,
    pub deviation_bps: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_oracle_source_excluded(
    env: &Env,
    source: Address,
    price_micros: i128,
    median_price_micros: i128,
    deviation_bps: u32,
    timestamp: u64,
) {
    OracleSourceExcludedEvent {
        source,
        schema_version: EVENT_SCHEMA_VERSION,
        price_micros,
        median_price_micros,
        deviation_bps,
        timestamp,
    }
    .publish(env);
}
