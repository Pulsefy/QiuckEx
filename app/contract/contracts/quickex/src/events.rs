use soroban_sdk::{Env, Address, Symbol};

pub(crate) fn publish_privacy_toggled(env: &Env, owner: Address, enabled: bool, timestamp: u64) {
    let topics = (Symbol::new(env, "PrivacyToggled"), owner);
    env.events().publish(topics, (enabled, timestamp));
}
