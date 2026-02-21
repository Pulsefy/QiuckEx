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

/// QuickEx Privacy Contract
///
/// Soroban smart contract providing escrow, privacy controls, and X-Ray-style amount
/// commitments for the QuickEx platform. See the contract README for main flows.
#[contract]
pub struct QuickexContract;

#[contractimpl]
impl QuickexContract {
    /// Withdraw escrowed funds by proving commitment ownership.
    ///
    /// The caller (`to`) must authorize; the commitment is recomputed from `to`, `amount`, and `salt`
    /// and must match an existing pending escrow entry.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `_token` - Reserved; token is stored in the escrow entry
    /// * `amount` - Amount to withdraw; must be positive and match the escrow amount
    /// * `_commitment` - Reserved; commitment is derived from `to`, `amount`, `salt`
    /// * `to` - Recipient address (must authorize the call)
    /// * `salt` - Salt used when creating the original deposit commitment
    ///
    /// # Errors
    /// * `InvalidAmount` - Amount is zero or negative
    /// * `CommitmentNotFound` - No escrow exists for the computed commitment
    /// * `AlreadySpent` - Escrow has already been withdrawn or marked spent
    /// * `InvalidCommitment` - Escrow amount does not match the requested amount
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

    /// Set a numeric privacy level for an account (legacy/level-based API).
    ///
    /// Records the level in storage and appends it to the account's privacy history.
    /// For boolean on/off privacy, prefer [`set_privacy`](QuickexContract::set_privacy).
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `account` - The account to configure
    /// * `privacy_level` - Numeric level (0 = off, higher = more privacy; interpretation is application-specific)
    pub fn enable_privacy(env: Env, account: Address, privacy_level: u32) -> bool {
        set_privacy_level(&env, &account, privacy_level);
        add_privacy_history(&env, &account, privacy_level);
        true
    }

    /// Get the current numeric privacy level for an account.
    ///
    /// Returns `None` if no level has been set.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `account` - The account to query
    pub fn privacy_status(env: Env, account: Address) -> Option<u32> {
        get_privacy_level(&env, &account)
    }

    /// Get the history of privacy level changes for an account.
    ///
    /// Returns a vector of levels in chronological order (oldest first).
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `account` - The account to query
    pub fn privacy_history(env: Env, account: Address) -> Vec<u32> {
        get_privacy_history(&env, &account)
    }

    /// Enable or disable privacy for an account.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The account address to configure
    /// * `enabled` - `true` to enable privacy, `false` to disable
    ///
    /// # Errors
    /// * `PrivacyAlreadySet` - Privacy state is already at the requested value
    /// * `InvalidPrivacyLevel` - Invalid internal state (e.g. invalid level transition)
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

    /// Deposit funds and create an escrow entry keyed by a commitment hash.
    ///
    /// Transfers `amount` from `owner` to the contract and stores an escrow keyed by
    /// `SHA256(owner || amount || salt)`. The owner must authorize the transfer.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `token` - The token contract address
    /// * `amount` - Amount to deposit; must be positive
    /// * `owner` - Owner of the funds (must authorize)
    /// * `salt` - Random salt (0–1024 bytes) for uniqueness; same inputs = same commitment
    ///
    /// # Errors
    /// * `InvalidAmount` - Amount is zero or negative
    /// * `InvalidSalt` - Salt length exceeds 1024 bytes
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

    /// Create a deterministic commitment hash for an amount (off-chain / pre-deposit use).
    ///
    /// Computes `SHA256(owner || amount || salt)`. Not a zero-knowledge proof; same inputs
    /// always yield the same hash. Use for API shape validation and audit trails.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `owner` - The owner address
    /// * `amount` - Non-negative amount in token base units
    /// * `salt` - Random bytes (0–1024 bytes) for uniqueness
    ///
    /// # Errors
    /// * `InvalidAmount` - Amount is negative
    /// * `InvalidSalt` - Salt length exceeds 1024 bytes
    pub fn create_amount_commitment(
        env: Env,
        owner: Address,
        amount: i128,
        salt: Bytes,
    ) -> Result<BytesN<32>, QuickexError> {
        commitment::create_amount_commitment(&env, owner, amount, salt)
    }

    /// Verify that a commitment hash matches the given `owner`, `amount`, and `salt`.
    ///
    /// Recomputes the commitment and compares. Returns `false` if inputs are invalid or don't match.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `commitment` - 32-byte commitment hash to verify
    /// * `owner` - Claimed owner
    /// * `amount` - Claimed amount (must be non-negative)
    /// * `salt` - Salt used when creating the commitment
    pub fn verify_amount_commitment(
        env: Env,
        commitment: BytesN<32>,
        owner: Address,
        amount: i128,
        salt: Bytes,
    ) -> bool {
        commitment::verify_amount_commitment(&env, commitment, owner, amount, salt)
    }

    /// Create an escrow record and increment the global escrow counter.
    ///
    /// Returns the new counter value. Parameters `_from`, `_to`, `_amount` are reserved for
    /// future use; the implementation only increments the counter.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `_from` - Reserved (depositor address for future use)
    /// * `_to` - Reserved (recipient address for future use)
    /// * `_amount` - Reserved (amount for future use)
    pub fn create_escrow(env: Env, _from: Address, _to: Address, _amount: u64) -> u64 {
        increment_escrow_counter(&env)
    }

    /// Health check for deployment and monitoring.
    ///
    /// Returns `true` if the contract is deployed and callable. No state or auth required.
    pub fn health_check() -> bool {
        true
    }

    /// Deposit funds using a pre-generated 32-byte commitment hash.
    ///
    /// Transfers `amount` from `from` to the contract and stores an escrow keyed by
    /// `commitment`. The depositor must authorize. Use when the commitment was created
    /// off-chain or via [`create_amount_commitment`](QuickexContract::create_amount_commitment).
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `from` - Depositor (must authorize the token transfer)
    /// * `token` - Token contract address
    /// * `amount` - Amount to deposit; must be positive
    /// * `commitment` - 32-byte commitment hash (must be unique)
    ///
    /// # Errors
    /// * `InvalidAmount` - Amount is zero or negative
    /// * `CommitmentAlreadyExists` - An escrow for this commitment already exists
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

    /// Initialize the contract with an admin address (one-time only).
    ///
    /// Sets the admin who can pause/unpause, transfer admin, and upgrade the contract.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `admin` - The admin address to set
    ///
    /// # Errors
    /// * `AlreadyInitialized` - Contract has already been initialized
    pub fn initialize(env: Env, admin: Address) -> Result<(), QuickexError> {
        if get_admin(&env).is_some() {
            return Err(QuickexError::AlreadyInitialized);
        }
        set_admin(&env, &admin);
        Ok(())
    }

    /// Pause or unpause the contract (**Admin only**).
    ///
    /// When paused, certain operations may be blocked. Caller must equal the stored admin.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `caller` - Caller address (must equal admin)
    /// * `new_state` - `true` to pause, `false` to unpause
    ///
    /// # Errors
    /// * `Unauthorized` - Caller is not the admin, or admin not set
    pub fn set_paused(env: Env, caller: Address, new_state: bool) -> Result<(), QuickexError> {
        let admin = get_admin(&env).ok_or(QuickexError::Unauthorized)?;
        if caller != admin {
            return Err(QuickexError::Unauthorized);
        }
        set_paused(&env, new_state);
        Ok(())
    }

    /// Transfer admin rights to a new address (**Admin only**).
    ///
    /// Caller must equal the current admin. The new admin can later transfer again.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `caller` - Caller address (must equal current admin)
    /// * `new_admin` - New admin address
    ///
    /// # Errors
    /// * `Unauthorized` - Caller is not the admin, or admin not set
    pub fn set_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), QuickexError> {
        let admin = get_admin(&env).ok_or(QuickexError::Unauthorized)?;
        if caller != admin {
            return Err(QuickexError::Unauthorized);
        }
        set_admin(&env, &new_admin);
        Ok(())
    }

    /// Check if the contract is currently paused.
    ///
    /// Returns `true` if paused, `false` otherwise.
    pub fn is_paused(env: Env) -> bool {
        is_paused(&env)
    }

    /// Get the current admin address.
    ///
    /// Returns `None` if the contract has not been initialized.
    pub fn get_admin(env: Env) -> Option<Address> {
        get_admin(&env)
    }

    /// Get the status of an escrow by its commitment hash (read-only).
    ///
    /// Returns `Pending`, `Spent`, or `Expired` if an escrow exists; `None` otherwise.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `commitment` - 32-byte commitment hash used as the escrow key
    pub fn get_commitment_state(env: Env, commitment: BytesN<32>) -> Option<EscrowStatus> {
        let commitment_bytes: Bytes = commitment.into();
        let entry: Option<EscrowEntry> = get_escrow(&env, &commitment_bytes);

        entry.map(|e| e.status)
    }

    /// Verify withdrawal parameters without submitting a transaction (read-only).
    ///
    /// Recomputes the commitment from `amount`, `salt`, and `owner`, then checks that an
    /// escrow exists with status `Pending` and matching amount. Use before calling `withdraw`.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `amount` - Amount to verify (non-negative)
    /// * `salt` - Salt used when creating the deposit
    /// * `owner` - Owner of the escrow
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

    /// Get full escrow details for a commitment hash (read-only).
    ///
    /// Returns the full `EscrowEntry` (token, amount, owner, status, created_at) if it exists.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `commitment` - 32-byte commitment hash
    pub fn get_escrow_details(env: Env, commitment: BytesN<32>) -> Option<EscrowEntry> {
        let commitment_bytes: Bytes = commitment.into();
        get_escrow(&env, &commitment_bytes)
    }
    /// Upgrade the contract to a new WASM implementation (**Admin only**).
    ///
    /// Caller must equal admin and authorize. The new WASM must be pre-uploaded to the network.
    /// Emits an upgrade event for audit.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `caller` - Caller address (must equal admin; must authorize)
    /// * `new_wasm_hash` - 32-byte hash of the new WASM code
    ///
    /// # Errors
    /// * `Unauthorized` - Caller is not the admin, or admin not set
    ///
    /// # Security
    /// Updates the contract's executable code. Use with care in production.
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
