#![no_std]
use soroban_sdk::{Address, Bytes, BytesN, Env, Map, Symbol, Vec, contract, contractimpl, token};

mod commitment;
mod errors;
mod events;
mod privacy;
mod types;

use errors::QuickexError;
use events::publish_withdraw_toggled;
use types::{EscrowEntry, EscrowStatus};

/// Main contract structure
#[contract]
pub struct QuickexContract;

#[contractimpl]
impl QuickexContract {
    /// Withdraw funds by proving commitment ownership
    pub fn withdraw(
        env: Env,
        to: Address,
        amount: i128,
        salt: Bytes,
    ) -> Result<bool, QuickexError> {
        if amount <= 0 {
            return Err(QuickexError::InvalidAmount);
        }

        to.require_auth();

        let commitment = commitment::create_amount_commitment(&env, to.clone(), amount, salt);

        let escrow_key = Symbol::new(&env, "escrow");
        let entry: EscrowEntry = env
            .storage()
            .persistent()
            .get(&(escrow_key.clone(), commitment.clone()))
            .ok_or(QuickexError::CommitmentNotFound)?;

        if entry.status != EscrowStatus::Pending {
            return Err(QuickexError::AlreadySpent);
        }

        if entry.amount != amount {
            return Err(QuickexError::InvalidCommitment);
        }

        let mut updated_entry = entry.clone();
        updated_entry.status = EscrowStatus::Spent;
        env.storage()
            .persistent()
            .set(&(escrow_key, commitment.clone()), &updated_entry);

        let token_client = token::Client::new(&env, &entry.token);
        token_client.transfer(&env.current_contract_address(), &to, &amount);

        publish_withdraw_toggled(&env, to, commitment?);

        Ok(true)
    }

    pub fn enable_privacy(env: Env, account: Address, privacy_level: u32) -> bool {
        let key = Symbol::new(&env, "privacy_level");
        env.storage()
            .persistent()
            .set(&(key, account.clone()), &privacy_level);

        let history_key = Symbol::new(&env, "privacy_history");
        let mut history: Vec<u32> = env
            .storage()
            .persistent()
            .get(&(history_key.clone(), account.clone()))
            .unwrap_or(Vec::new(&env));

        history.push_front(privacy_level);
        env.storage()
            .persistent()
            .set(&(history_key, account), &history);

        true
    }

    pub fn privacy_status(env: Env, account: Address) -> Option<u32> {
        let key = Symbol::new(&env, "privacy_level");
        env.storage().persistent().get(&(key, account))
    }

    pub fn privacy_history(env: Env, account: Address) -> Vec<u32> {
        let key = Symbol::new(&env, "privacy_history");
        env.storage()
            .persistent()
            .get(&(key, account))
            .unwrap_or(Vec::new(&env))
    }

    /// Enable or disable privacy for an account
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The account address to configure
    /// * `enabled` - True to enable privacy, False to disable
    ///
    /// # Returns
    /// * `Result<(), QuickexError>` - Ok if successful, Error otherwise
    pub fn set_privacy(env: Env, owner: Address, enabled: bool) -> Result<(), QuickexError> {
        privacy::set_privacy(&env, owner, enabled)
    }

    /// Check the current privacy status of an account
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The account address to query
    ///
    /// # Returns
    /// * `bool` - Current privacy status (true = enabled)
    pub fn get_privacy(env: Env, owner: Address) -> bool {
        privacy::get_privacy(&env, owner)
    }

    /// Create a commitment for a hidden amount
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The owner of the funds
    /// * `amount` - The amount to commit
    /// * `salt` - Random salt for privacy
    ///
    /// # Returns
    /// * `Result<BytesN<32>, QuickexError>` - The commitment hash
    pub fn create_amount_commitment(
        env: Env,
        owner: Address,
        amount: i128,
        salt: Bytes,
    ) -> Result<BytesN<32>, QuickexError> {
        commitment::create_amount_commitment(&env, owner, amount, salt)
    }

    /// Verify a commitment matches the provided values
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `commitment` - The commitment hash to verify
    /// * `owner` - The owner of the funds
    /// * `amount` - The amount to verify
    /// * `salt` - The salt used for the commitment
    ///
    /// # Returns
    /// * `bool` - True if valid
    pub fn verify_amount_commitment(
        env: Env,
        commitment: BytesN<32>,
        owner: Address,
        amount: i128,
        salt: Bytes,
    ) -> bool {
        commitment::verify_amount_commitment(&env, commitment, owner, amount, salt)
    }

    pub fn create_escrow(env: Env, from: Address, to: Address, _amount: u64) -> u64 {
        let counter_key = Symbol::new(&env, "escrow_counter");
        let mut count: u64 = env.storage().persistent().get(&counter_key).unwrap_or(0);
        count += 1;
        env.storage().persistent().set(&counter_key, &count);

        let escrow_id = count;
        let escrow_key = Symbol::new(&env, "escrow");
        let mut escrow_details = Map::<Symbol, Address>::new(&env);
        escrow_details.set(Symbol::new(&env, "from"), from);
        escrow_details.set(Symbol::new(&env, "to"), to);

        env.storage()
            .persistent()
            .set(&(escrow_key, escrow_id), &escrow_details);

        escrow_id
    }

    pub fn health_check() -> bool {
        true
    }
}

mod test;
