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
        _token: &Address,
        amount: i128,
        _commitment: BytesN<32>,
        to: Address,

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

    /// Deposit funds and create an escrow entry using a pre-generated commitment
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `from` - The address depositing the funds
    /// * `token` - The token address
    /// * `amount` - The amount to deposit
    /// * `commitment` - The pre-generated commitment hash
    ///
    /// # Returns
    /// * `Result<(), QuickexError>` - Ok if successful, Error otherwise
    pub fn deposit_with_commitment(
        env: Env,
        from: Address,
        token: Address,
        amount: i128,
        commitment: BytesN<32>,
    ) -> Result<(), QuickexError> {
        if amount <= 0 {
            return Err(QuickexError::InvalidAmount);
        }

        from.require_auth();

        if has_escrow(&env, &commitment.clone().into()) {
            return Err(QuickexError::CommitmentAlreadyExists);
        }

        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&from, env.current_contract_address(), &amount);

        let entry = EscrowEntry {
            token: token.clone(),
            amount,
            owner: from.clone(),
            status: EscrowStatus::Pending,
            created_at: env.ledger().timestamp(),
        };

        put_escrow(&env, &commitment.clone().into(), &entry);

        events::publish_deposit(&env, commitment, token, amount);

        Ok(())
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

    pub fn get_commitment_state(env: Env, commitment: BytesN<32>) -> Option<EscrowStatus> {
        let commitment_bytes: Bytes = commitment.into();
        let entry: Option<EscrowEntry> = get_escrow(&env, &commitment_bytes);

        entry.map(|e| e.status)
    }

    // Verify proof parameters without submitting a transaction
    pub fn verify_proof_view(env: Env, amount: i128, salt: Bytes, owner: Address) -> bool {
        let commitment_result =
            commitment::create_amount_commitment(&env, owner.clone(), amount, salt);

        let commitment = match commitment_result {
            Ok(c) => c,
            Err(_) => return false,
        };

        // Check if commitment exists in storage
        let commitment_bytes: Bytes = commitment.into();
        let entry: Option<EscrowEntry> = get_escrow(&env, &commitment_bytes);

        // Verify the entry exists, is pending, and amount matches
        match entry {
            Some(e) => e.status == EscrowStatus::Pending && e.amount == amount,
            None => false,
        }
    }

    // Get detailed escrow information for a commitment
    pub fn get_escrow_details(env: Env, commitment: BytesN<32>) -> Option<EscrowEntry> {
        let commitment_bytes: Bytes = commitment.into();
        get_escrow(&env, &commitment_bytes)
    }
    /// Upgrade the contract to a new WASM implementation (Admin only)
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `caller` - The caller address (must be admin)
    /// * `new_wasm_hash` - The hash of the new WASM code to upgrade to
    ///
    /// # Returns
    /// * `Result<(), QuickexError>` - Ok if successful, Error if unauthorized
    ///
    /// # Security
    /// This function requires admin authorization and will update the contract's
    /// executable code. The new WASM must be pre-uploaded to the network.
    pub fn upgrade(
        env: Env,
        caller: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), QuickexError> {
        // Verify caller is admin
        let admin = get_admin(&env).ok_or(QuickexError::Unauthorized)?;
        if caller != admin {
            return Err(QuickexError::Unauthorized);
        }

        // Require cryptographic authorization from the caller
        caller.require_auth();

        // Update the contract WASM to the new implementation
        env.deployer()
            .update_current_contract_wasm(new_wasm_hash.clone());

        // Emit upgrade event for audit trail
        let timestamp = env.ledger().timestamp();
        events::publish_contract_upgraded(&env, new_wasm_hash, &admin, timestamp);

        Ok(())
    }
}

mod storage_test;
mod test;
