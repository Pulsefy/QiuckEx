#![no_std]
use soroban_sdk::{contract, contractimpl, token, Address, Bytes, BytesN, Env, Vec};

mod admin;
mod commitment;
mod errors;
mod events;
mod privacy;
mod storage;
mod types;

use errors::QuickexError;
use events::publish_withdraw_toggled;
use storage::*;
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

        let commitment = commitment::create_amount_commitment(&env, to.clone(), amount, salt)?;

        let entry: EscrowEntry =
            get_escrow(&env, &commitment.clone().into()).ok_or(QuickexError::CommitmentNotFound)?;

        if entry.status != EscrowStatus::Pending {
            return Err(QuickexError::AlreadySpent);
        }

        if entry.amount != amount {
            return Err(QuickexError::InvalidCommitment);
        }

        let mut updated_entry = entry.clone();
        updated_entry.status = EscrowStatus::Spent;
        put_escrow(&env, &commitment.clone().into(), &updated_entry);

        let token_client = token::Client::new(&env, &entry.token);
        token_client.transfer(&env.current_contract_address(), &to, &amount);

        publish_withdraw_toggled(&env, to, commitment);

        Ok(true)
    }

    pub fn enable_privacy(env: Env, account: Address, privacy_level: u32) -> bool {
        set_privacy_level(&env, &account, privacy_level);
        add_privacy_history(&env, &account, privacy_level);
        true
    }

    pub fn privacy_status(env: Env, account: Address) -> Option<u32> {
        get_privacy_level(&env, &account)
    }

    pub fn privacy_history(env: Env, account: Address) -> Vec<u32> {
        get_privacy_history(&env, &account)
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

    /// Deposit funds and create an escrow entry
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `token` - The token address
    /// * `amount` - The amount to deposit
    /// * `owner` - The owner of the funds
    /// * `salt` - Random salt for privacy
    ///
    /// # Returns
    /// * `Result<BytesN<32>, QuickexError>` - The commitment hash
    pub fn deposit(
        env: Env,
        token: Address,
        amount: i128,
        owner: Address,
        salt: Bytes,
    ) -> Result<BytesN<32>, QuickexError> {
        if amount <= 0 {
            return Err(QuickexError::InvalidAmount);
        }

        owner.require_auth();

        let commitment = commitment::create_amount_commitment(&env, owner.clone(), amount, salt)?;

        let entry = EscrowEntry {
            token: token.clone(),
            amount,
            owner: owner.clone(),
            status: EscrowStatus::Pending,
            created_at: env.ledger().timestamp(),
        };

        put_escrow(&env, &commitment.clone().into(), &entry);

        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&owner, env.current_contract_address(), &amount);

        Ok(commitment)
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

    pub fn create_escrow(env: Env, _from: Address, _to: Address, _amount: u64) -> u64 {
        increment_escrow_counter(&env)
    }

    pub fn health_check() -> bool {
        true
    }

    /// Initialize the contract with an admin address
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `admin` - The admin address to set
    ///
    /// # Returns
    /// * `Result<(), QuickexError>` - Ok if successful, Error if already initialized
    pub fn initialize(env: Env, admin: Address) -> Result<(), QuickexError> {
        if get_admin(&env).is_some() {
            return Err(QuickexError::AlreadyInitialized);
        }
        set_admin(&env, &admin);
        Ok(())
    }

    /// Set the paused state of the contract (Admin only)
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `caller` - The caller address (must be admin)
    /// * `new_state` - True to pause, False to unpause
    ///
    /// # Returns
    /// * `Result<(), QuickexError>` - Ok if successful, Error if unauthorized or other issue
    pub fn set_paused(env: Env, caller: Address, new_state: bool) -> Result<(), QuickexError> {
        let admin = get_admin(&env).ok_or(QuickexError::Unauthorized)?;
        if caller != admin {
            return Err(QuickexError::Unauthorized);
        }
        set_paused(&env, new_state);
        Ok(())
    }

    /// Transfer admin rights to a new address (Admin only)
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `caller` - The caller address (must be admin)
    /// * `new_admin` - The new admin address
    ///
    /// # Returns
    /// * `Result<(), QuickexError>` - Ok if successful, Error if unauthorized or other issue
    pub fn set_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), QuickexError> {
        let admin = get_admin(&env).ok_or(QuickexError::Unauthorized)?;
        if caller != admin {
            return Err(QuickexError::Unauthorized);
        }
        set_admin(&env, &new_admin);
        Ok(())
    }

    /// Check if the contract is currently paused
    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    /// * `bool` - True if paused, False otherwise
    pub fn is_paused(env: Env) -> bool {
        is_paused(&env)
    }

    /// Get the current admin address
    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    /// * `Option<Address>` - The admin address if set, None otherwise
    pub fn get_admin(env: Env) -> Option<Address> {
        get_admin(&env)
    }
}

mod storage_test;
mod test;
