use soroban_sdk::{contractevent, Address, BytesN, Env};

#[contractevent(topics = ["TOPIC_PRIVACY", "PrivacyToggled"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyToggledEvent {
    #[topic]
    pub owner: Address,

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

    pub token: Address,
    pub amount: i128,
    pub timestamp: u64,
}

#[contractevent(topics = ["TOPIC_ESCROW", "EscrowDeposited"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowDepositedEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub owner: Address,

    pub token: Address,
    pub amount: i128,
    pub expires_at: u64,
    pub timestamp: u64,
}

pub(crate) fn publish_privacy_toggled(env: &Env, owner: Address, enabled: bool) {
    PrivacyToggledEvent {
        owner,
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

    pub paused: bool,
    pub timestamp: u64,
}

#[allow(dead_code)]
pub(crate) fn publish_contract_paused(env: &Env, admin: Address, paused: bool) {
    ContractPausedEvent {
        admin,
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

    pub timestamp: u64,
}

#[allow(dead_code)]
pub(crate) fn publish_admin_changed(env: &Env, old_admin: Address, new_admin: Address) {
    AdminChangedEvent {
        old_admin,
        new_admin,
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

    pub timestamp: u64,
}

pub(crate) fn publish_contract_upgraded(env: &Env, new_wasm_hash: BytesN<32>, admin: &Address) {
    ContractUpgradedEvent {
        new_wasm_hash,
        admin: admin.clone(),
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
) {
    EscrowWithdrawnEvent {
        escrow_id: commitment,
        owner,
        token,
        amount,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

pub(crate) fn publish_escrow_deposited(
    env: &Env,
    commitment: BytesN<32>,
    owner: Address,
    token: Address,
    amount: i128,
    expires_at: u64,
) {
    EscrowDepositedEvent {
        escrow_id: commitment,
        owner,
        token,
        amount,
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

    pub token: Address,
    pub amount: i128,
    pub timestamp: u64,
}

#[contractevent(topics = ["TOPIC_ESCROW", "EscrowDisputed"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowDisputedEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub arbiter: Address,

    pub timestamp: u64,
}

pub(crate) fn publish_escrow_disputed(env: &Env, commitment: BytesN<32>, arbiter: Address) {
    EscrowDisputedEvent {
        escrow_id: commitment,
        arbiter,
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
        token,
        amount,
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

    pub token: Address,
    pub amount: i128,
    pub expires_at: u64,
    pub timestamp: u64,
}

pub(crate) fn publish_ephemeral_key_registered(
    env: &Env,
    stealth_address: BytesN<32>,
    eph_pub: BytesN<32>,
    token: Address,
    amount: i128,
    expires_at: u64,
) {
    EphemeralKeyRegisteredEvent {
        stealth_address,
        eph_pub,
        token,
        amount,
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
        token,
        amount,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}
