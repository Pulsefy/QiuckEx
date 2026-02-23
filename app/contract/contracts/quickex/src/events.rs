use soroban_sdk::{contractevent, Address, BytesN, Env};

#[contractevent(topics = ["PrivacyToggled"]) ]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyToggledEvent {
    #[topic]
    pub owner: Address,

    pub enabled: bool,
    pub timestamp: u64,
}

#[contractevent(topics = ["EscrowWithdrawn"]) ]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowWithdrawnEvent {
    #[topic]
    pub commitment: BytesN<32>,

    #[topic]
    pub owner: Address,

    pub token: Address,
    pub amount: i128,
    pub timestamp: u64,
}

#[contractevent(topics = ["EscrowDeposited"]) ]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowDepositedEvent {
    #[topic]
    pub commitment: BytesN<32>,

    #[topic]
    pub owner: Address,

    pub token: Address,
    pub amount: i128,
    pub expires_at: u64,
    pub timestamp: u64,
}

pub(crate) fn publish_privacy_toggled(env: &Env, owner: Address, enabled: bool, timestamp: u64) {
    PrivacyToggledEvent {
        owner,
        enabled,
        timestamp,
    }
    .publish(env);
}

#[allow(dead_code)]
#[contractevent(topics = ["ContractPaused"]) ]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractPausedEvent {
    #[topic]
    pub admin: Address,

    pub paused: bool,
    pub timestamp: u64,
}

#[allow(dead_code)]
pub(crate) fn publish_contract_paused(env: &Env, admin: Address, paused: bool, timestamp: u64) {
    ContractPausedEvent {
        admin,
        paused,
        timestamp,
    }
    .publish(env);
}

#[allow(dead_code)]
#[contractevent(topics = ["AdminChanged"]) ]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChangedEvent {
    #[topic]
    pub old_admin: Address,

    #[topic]
    pub new_admin: Address,

    pub timestamp: u64,
}

#[allow(dead_code)]
pub(crate) fn publish_admin_changed(
    env: &Env,
    old_admin: Address,
    new_admin: Address,
    timestamp: u64,
) {
    AdminChangedEvent {
        old_admin,
        new_admin,
        timestamp,
    }
    .publish(env);
}

#[contractevent(topics = ["ContractUpgraded"]) ]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractUpgradedEvent {
    #[topic]
    pub new_wasm_hash: BytesN<32>,

    #[topic]
    pub admin: Address,

    pub timestamp: u64,
}

pub(crate) fn publish_contract_upgraded(
    env: &Env,
    new_wasm_hash: BytesN<32>,
    admin: &Address,
    timestamp: u64,
) {
    ContractUpgradedEvent {
        new_wasm_hash,
        admin: admin.clone(),
        timestamp,
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
        commitment,
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
        commitment,
        owner,
        token,
        amount,
        expires_at,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

#[contractevent(topics = ["EscrowRefunded"]) ]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowRefundedEvent {
    #[topic]
    pub owner: Address,

    #[topic]
    pub commitment: BytesN<32>,

    pub token: Address,
    pub amount: i128,
    pub timestamp: u64,
}

pub(crate) fn publish_escrow_refunded(
    env: &Env,
    owner: Address,
    commitment: BytesN<32>,
    token: Address,
    amount: i128,
) {
    EscrowRefundedEvent {
        owner,
        commitment,
        token,
        amount,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}
