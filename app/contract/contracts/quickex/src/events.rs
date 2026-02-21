use soroban_sdk::{contractevent, Address, BytesN, Env};

#[contractevent(topics = ["PrivacyToggled"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyToggledEvent {
    #[topic]
    pub owner: Address,

    pub enabled: bool,
    pub timestamp: u64,
}

#[contractevent(topics = ["WithdrawToggled"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawToggledEvent {
    pub to: Address,
    pub commitment: BytesN<32>,
    pub timestamp: u64,
}

#[contractevent(topics = ["Deposit"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositToggledEvent {
    pub commitment: BytesN<32>,
    pub token: Address,
    pub amount: i128,
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
#[contractevent(topics = ["ContractPaused"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractPausedEvent {
    pub paused: bool,
    pub timestamp: u64,
}

#[allow(dead_code)]
pub(crate) fn publish_contract_paused(env: &Env, paused: bool, timestamp: u64) {
    ContractPausedEvent { paused, timestamp }.publish(env);
}

#[allow(dead_code)]
#[contractevent(topics = ["AdminChanged"])]
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

#[contractevent(topics = ["ContractUpgraded"])]
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

pub(crate) fn publish_withdraw_toggled(env: &Env, to: Address, commitment: BytesN<32>) {
    WithdrawToggledEvent {
        to,
        commitment,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}

pub(crate) fn publish_deposit(env: &Env, commitment: BytesN<32>, token: Address, amount: i128) {
    DepositToggledEvent {
        commitment,
        token,
        amount,
    }
    .publish(env);
}

#[contractevent(topics = ["Refunded"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundedEvent {
    #[topic]
    pub owner: Address,
    pub commitment: BytesN<32>,
    pub amount: i128,
    pub timestamp: u64,
}

pub(crate) fn publish_refunded(env: &Env, owner: Address, commitment: BytesN<32>, amount: i128) {
    RefundedEvent {
        owner,
        commitment,
        amount,
        timestamp: env.ledger().timestamp(),
    }
    .publish(env);
}
