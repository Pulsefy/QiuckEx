use soroban_sdk::{Address, BytesN, Env, contractevent};

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

pub(crate) fn publish_privacy_toggled(env: &Env, owner: Address, enabled: bool, timestamp: u64) {
    PrivacyToggledEvent {
        owner,
        enabled,
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
