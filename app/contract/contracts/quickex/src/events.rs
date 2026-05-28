use soroban_sdk::{contractevent, Address, BytesN, Env};

/// Canonical event schema version.
///
/// Increment this constant whenever the event payload shape changes
/// (fields added, removed, or renamed). Indexers MUST check this field
/// before parsing any event payload so they can route to the correct
/// decoder for the schema version they understand.
///
/// History:
///   v1 – original schema (no version field)
///   v2 – added `schema_version` to every event payload (this release)
pub const EVENT_SCHEMA_VERSION: u32 = 2;

/// Testnet event topic namespace used as topic[0] for every QuickEx event.
pub const EVENT_TOPIC_ADMIN: &str = "TOPIC_ADMIN";
pub const EVENT_TOPIC_DISPUTE: &str = "TOPIC_DISPUTE";
pub const EVENT_TOPIC_ESCROW: &str = "TOPIC_ESCROW";
pub const EVENT_TOPIC_PRIVACY: &str = "TOPIC_PRIVACY";
pub const EVENT_TOPIC_STEALTH: &str = "TOPIC_STEALTH";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventSchema {
    pub name: &'static str,
    pub topics: &'static [&'static str],
    pub payload_keys: &'static [&'static str],
    pub schema_version: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventCompatibility {
    pub name: &'static str,
    pub current_version: u32,
    pub compatible_versions: &'static [u32],
}

pub const EVENT_SCHEMAS: &[EventSchema] = &[
    EventSchema {
        name: "AdminChanged",
        topics: &[EVENT_TOPIC_ADMIN, "AdminChanged", "old_admin", "new_admin"],
        payload_keys: &["schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "ArbiterVoteCast",
        topics: &[EVENT_TOPIC_DISPUTE, "ArbiterVoteCast", "escrow_id", "arbiter"],
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
        name: "ContractPaused",
        topics: &[EVENT_TOPIC_ADMIN, "ContractPaused", "admin"],
        payload_keys: &["paused", "schema_version", "timestamp"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "ContractUpgraded",
        topics: &[EVENT_TOPIC_ADMIN, "ContractUpgraded", "new_wasm_hash", "admin"],
        payload_keys: &["schema_version", "timestamp"],
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
        payload_keys: &["amount", "schema_version", "threshold", "timestamp", "total_votes"],
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
        payload_keys: &["schema_version", "timestamp", "token", "total_amount"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "EscrowRefunded",
        topics: &[EVENT_TOPIC_ESCROW, "EscrowRefunded", "escrow_id", "owner"],
        payload_keys: &["amount", "schema_version", "timestamp", "token"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
    EventSchema {
        name: "EscrowWithdrawn",
        topics: &[EVENT_TOPIC_ESCROW, "EscrowWithdrawn", "escrow_id", "owner"],
        payload_keys: &["amount", "fee", "schema_version", "timestamp", "token"],
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
        payload_keys: &["fee_bps", "schema_version", "timestamp"],
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
        payload_keys: &["arbiter_bps", "fee_bps", "schema_version", "timestamp"],
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
        topics: &[EVENT_TOPIC_STEALTH, "StealthWithdrawn", "stealth_address", "recipient"],
        payload_keys: &["amount", "schema_version", "timestamp", "token"],
        schema_version: EVENT_SCHEMA_VERSION,
    },
];

pub const EVENT_COMPATIBILITY: &[EventCompatibility] = &[
    EventCompatibility {
        name: "AdminChanged",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[1, EVENT_SCHEMA_VERSION],
    },
    EventCompatibility {
        name: "EscrowDeposited",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[1, EVENT_SCHEMA_VERSION],
    },
    EventCompatibility {
        name: "EscrowRefunded",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[1, EVENT_SCHEMA_VERSION],
    },
    EventCompatibility {
        name: "EscrowWithdrawn",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[1, EVENT_SCHEMA_VERSION],
    },
    EventCompatibility {
        name: "PrivacyToggled",
        current_version: EVENT_SCHEMA_VERSION,
        compatible_versions: &[1, EVENT_SCHEMA_VERSION],
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
#[contractevent(topics = ["TOPIC_ADMIN", "ContractPaused"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractPausedEvent {
    #[topic]
    pub admin: Address,

    pub schema_version: u32,
    pub paused: bool,
    pub timestamp: u64,
}

#[allow(dead_code)]
pub(crate) fn publish_contract_paused(env: &Env, admin: Address, paused: bool) {
    ContractPausedEvent {
        admin,
        schema_version: EVENT_SCHEMA_VERSION,
        paused,
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

pub(crate) fn publish_contract_upgraded(env: &Env, new_wasm_hash: BytesN<32>, admin: &Address) {
    ContractUpgradedEvent {
        new_wasm_hash,
        admin: admin.clone(),
        schema_version: EVENT_SCHEMA_VERSION,
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
    EscrowWithdrawnEvent {
        escrow_id: commitment,
        owner,
        schema_version: EVENT_SCHEMA_VERSION,
        token,
        amount,
        fee,
        timestamp: env.ledger().timestamp(),
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
    EscrowDepositedEvent {
        escrow_id: commitment,
        owner,
        schema_version: EVENT_SCHEMA_VERSION,
        token,
        amount_due,
        amount_paid,
        expires_at,
        timestamp: env.ledger().timestamp(),
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
    EscrowRefundedEvent {
        escrow_id: commitment,
        owner,
        schema_version: EVENT_SCHEMA_VERSION,
        token,
        amount,
        timestamp: env.ledger().timestamp(),
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
    EscrowFinalizedEvent {
        escrow_id: commitment,
        owner,
        schema_version: EVENT_SCHEMA_VERSION,
        token,
        total_amount,
        timestamp: env.ledger().timestamp(),
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
    pub schema_version: u32,
    pub fee_bps: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_fee_config_changed(env: &Env, fee_bps: u32) {
    FeeConfigChangedEvent {
        schema_version: EVENT_SCHEMA_VERSION,
        fee_bps,
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

#[contractevent(topics = ["TOPIC_ADMIN", "PerAssetFeeSet"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerAssetFeeSetEvent {
    #[topic]
    pub token: Address,
    pub fee_bps: u32,
    pub arbiter_bps: u32,
    pub schema_version: u32,
    pub timestamp: u64,
}

pub(crate) fn publish_per_asset_fee_set(env: &Env, token: Address, fee_bps: u32, arbiter_bps: u32) {
    PerAssetFeeSetEvent {
        token,
        fee_bps,
        arbiter_bps,
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}
