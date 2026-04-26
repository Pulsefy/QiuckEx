#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Vec};

mod admin;
#[cfg(test)]
mod bench_test;
mod commitment;
#[cfg(test)]
mod commitment_test;
mod errors;
mod escrow;
mod escrow_id;
#[cfg(test)]
mod escrow_id_test;
mod events;
mod fee;
#[cfg(test)]
mod fee_test;
mod privacy;
#[cfg(test)]
mod role_test;
mod stealth;
#[cfg(test)]
mod stealth_test;
mod storage;
#[cfg(test)]
mod storage_test;
#[cfg(test)]
mod test;
#[cfg(test)]
mod test_context;
mod types;

use errors::QuickexError;
use storage::*;
use types::{
    EscrowEntry, EscrowStatus, FeeConfig, PrivacyAwareEscrowView, Role, StealthDepositParams,
};

/// QuickEx Privacy Contract
///
/// Soroban smart contract providing escrow, privacy controls, and X-Ray-style amount
/// commitments for the QuickEx platform. See the contract README for main flows.
///
/// ## Asset Support
///
/// This contract supports both Native XLM and Stellar Asset Contract (SAC) tokens:
/// - **Native XLM**: The native lumens of the Stellar network. Use the stellar
///   network's native asset address when calling deposit functions.
/// - **SAC Tokens**: Any token implemented via Stellar Asset Contracts (e.g., USDC,
///   custom tokens). Use the SAC contract address as the token parameter.
///
/// The contract uses Soroban's standardized token interface which works uniformly across
/// all asset types. No special wrap/unwrap logic is required from users.
///
/// ## Escrow State Machine
///
/// ```text
/// [*] --> Pending  : deposit() / deposit_with_commitment()
/// Pending --> Spent    : withdraw(proof)  [now < expires_at, or no expiry]
/// Pending --> Refunded : refund(owner)    [now >= expires_at]
/// Pending --> Disputed : dispute()        [any participant can call]
/// Disputed --> Spent   : resolve_dispute() [arbiter decides for recipient]
/// Disputed --> Refunded: resolve_dispute() [arbiter decides for owner]
/// ```
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
    /// * `commitment` - Commitment hash for the escrow being withdrawn
    /// * `to` - Recipient address (must authorize the call)
    /// * `salt` - Salt used when creating the original deposit commitment
    ///
    /// # Errors
    /// * `InvalidAmount` - Amount is zero or negative
    /// * `ContractPaused` - Contract is currently paused
    /// * `CommitmentMismatch` - Provided commitment does not match (`to`, `amount`, `salt`)
    /// * `CommitmentNotFound` - No escrow exists for the provided commitment
    /// * `EscrowExpired` - Escrow has passed its expiry timestamp
    /// * `AlreadySpent` - Escrow has already been withdrawn or refunded
    /// * `InvalidCommitment` - Escrow amount does not match the requested amount
    pub fn withdraw(
        env: Env,
        _token: &Address,
        amount: i128,
        _commitment: BytesN<32>,
        to: Address,
        salt: Bytes,
    ) -> Result<bool, QuickexError> {
        if admin::is_paused(&env) {
            return Err(QuickexError::ContractPaused);
        }
        if is_feature_paused(&env, PauseFlag::Withdrawal) {
            return Err(QuickexError::OperationPaused);
        }
        escrow::withdraw(&env, amount, to, salt)
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
    /// * `ContractPaused` - Contract is currently paused
    /// * `PrivacyAlreadySet` - Privacy state is already at the requested value
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

    /// Deposit funds and create an escrow entry keyed by `KECCAK256(owner || amount || salt)`.
    ///
    /// Transfers `amount` from `owner` to the contract and stores an escrow entry.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `token` - The token contract address
    /// * `amount` - Amount to deposit; must be positive
    /// * `owner` - Owner of the funds (must authorize)
    /// * `salt` - Random salt (0–1024 bytes) for uniqueness
    /// * `timeout_secs` - Seconds from now until the escrow expires (0 = no expiry)
    /// * `arbiter` - Optional arbiter address who can resolve disputes
    ///
    /// # Errors
    /// * `InvalidAmount` - Amount is zero or negative
    /// * `InvalidSalt` - Salt length exceeds 1024 bytes
    /// * `ContractPaused` - Contract is currently paused
    /// * `CommitmentAlreadyExists` - An escrow for this commitment already exists
    pub fn deposit(
        env: Env,
        token: Address,
        amount: i128,
        owner: Address,
        salt: Bytes,
        timeout_secs: u64,
        arbiter: Option<Address>,
    ) -> Result<BytesN<32>, QuickexError> {
        if admin::is_paused(&env) {
            return Err(QuickexError::ContractPaused);
        }
        if is_feature_paused(&env, PauseFlag::Deposit) {
            return Err(QuickexError::OperationPaused);
        }
        escrow::deposit(&env, token, amount, owner, salt, timeout_secs, arbiter)
    }

    /// Derive a deterministic 32-byte escrow id from the full creation payload.
    ///
    /// Issue #304: enables duplicate detection and idempotent re-submission.
    /// Same inputs always yield the same id; any change to `token`, `amount`,
    /// `owner`, `salt`, `timeout_secs`, or `arbiter` yields a different id
    /// (see [`escrow_id`] module for the canonical serialization).
    ///
    /// # Errors
    /// * `InvalidAmount` - Amount is negative
    /// * `InvalidSalt` - Salt length exceeds 1024 bytes
    pub fn derive_escrow_id(
        env: Env,
        token: Address,
        amount: i128,
        owner: Address,
        salt: Bytes,
        timeout_secs: u64,
        arbiter: Option<Address>,
    ) -> Result<BytesN<32>, QuickexError> {
        escrow_id::derive_escrow_id(&env, &token, amount, &owner, &salt, timeout_secs, &arbiter)
    }

    /// Look up the escrow commitment associated with a deterministic `escrow_id`.
    ///
    /// Returns `None` if no escrow has been created for this id yet.
    pub fn get_escrow_id_commitment(env: Env, escrow_id: BytesN<32>) -> Option<BytesN<32>> {
        storage::get_escrow_id_mapping(&env, &escrow_id)
    }

    /// Create a deterministic commitment hash for an amount (off-chain / pre-deposit use).
    ///
    /// Computes `KECCAK256(owner || amount || salt)`. Not a zero-knowledge proof; same inputs
    /// always yield the same hash. Legacy `SHA256(owner || amount || salt)` commitments remain
    /// accepted by verification paths for backwards compatibility.
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
    /// * `timeout_secs` - Seconds from now until the escrow expires (0 = no expiry)
    /// * `arbiter` - Optional arbiter address who can resolve disputes
    ///
    /// # Errors
    /// * `InvalidAmount` - Amount is zero or negative
    /// * `ContractPaused` - Contract is currently paused
    /// * `CommitmentAlreadyExists` - An escrow for this commitment already exists
    pub fn deposit_with_commitment(
        env: Env,
        from: Address,
        token: Address,
        amount: i128,
        commitment: BytesN<32>,
        timeout_secs: u64,
        arbiter: Option<Address>,
    ) -> Result<(), QuickexError> {
        if admin::is_paused(&env) {
            return Err(QuickexError::ContractPaused);
        }
        if is_feature_paused(&env, PauseFlag::DepositWithCommitment) {
            return Err(QuickexError::OperationPaused);
        }
        escrow::deposit_with_commitment(
            &env,
            from,
            token,
            amount,
            commitment,
            timeout_secs,
            arbiter,
        )
    }

    /// Refund an expired escrow back to its original owner.
    ///
    /// Can only be called after `expires_at` is reached. The caller must be the
    /// original depositor. The escrow must still be `Pending`.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `commitment` - 32-byte commitment hash identifying the escrow
    /// * `caller` - Must equal the original depositor (must authorize)
    ///
    /// # Errors
    /// * `CommitmentNotFound` - No escrow exists for the commitment
    /// * `AlreadySpent` - Escrow is already in a terminal state
    /// * `EscrowNotExpired` - Escrow has no expiry or has not yet expired
    /// * `InvalidOwner` - Caller is not the original owner
    pub fn refund(env: Env, commitment: BytesN<32>, caller: Address) -> Result<(), QuickexError> {
        if admin::is_paused(&env) {
            return Err(QuickexError::ContractPaused);
        }
        if is_feature_paused(&env, PauseFlag::Refund) {
            return Err(QuickexError::OperationPaused);
        }

        escrow::refund(&env, commitment, caller)
    }

    /// Cleanup terminal escrow entries to reclaim storage deposits.
    ///
    /// Only escrows in `Spent` or `Refunded` status can be removed.
    pub fn cleanup_escrow(env: Env, commitment: BytesN<32>) -> Result<(), QuickexError> {
        escrow::cleanup_escrow(&env, commitment)
    }

    /// Extend the storage TTL of an escrow record.
    ///
    /// Any user can call this to keep an escrow from being archived.
    pub fn extend_escrow_ttl(env: Env, commitment: BytesN<32>) -> Result<(), QuickexError> {
        escrow::extend_escrow_ttl(&env, commitment)
    }

    /// Initiate a dispute for a pending escrow, locking the funds.
    ///
    /// Any participant can call this function to start a dispute. The escrow must
    /// have an assigned arbiter and be in `Pending` status. Changes status to `Disputed`.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `commitment` - 32-byte commitment hash identifying the escrow
    ///
    /// # Errors
    /// * `CommitmentNotFound` - No escrow exists for the commitment
    /// * `NoArbiter` - No arbiter assigned to the escrow
    /// * `InvalidDisputeState` - Escrow is not in `Pending` status
    pub fn dispute(env: Env, commitment: BytesN<32>) -> Result<(), QuickexError> {
        if admin::is_paused(&env) {
            return Err(QuickexError::ContractPaused);
        }
        escrow::dispute(&env, commitment)
    }

    /// Resolve a disputed escrow by determining the recipient of funds.
    ///
    /// Only callable by the assigned arbiter. The arbiter decides whether funds
    /// go to the original owner (refund) or to a specified recipient (spend).
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `commitment` - 32-byte commitment hash identifying the escrow
    /// * `resolve_for_owner` - If true, funds go to owner; if false, funds go to recipient
    /// * `recipient` - Address to receive funds when resolve_for_owner is false
    ///
    /// # Errors
    /// * `CommitmentNotFound` - No escrow exists for the commitment
    /// * `NotArbiter` - Caller is not the assigned arbiter
    /// * `NoArbiter` - No arbiter assigned to the escrow
    /// * `InvalidDisputeState` - Escrow is not in `Disputed` status
    pub fn resolve_dispute(
        env: Env,
        caller: Address,
        commitment: BytesN<32>,
        resolve_for_owner: bool,
        recipient: Address,
    ) -> Result<(), QuickexError> {
        if admin::is_paused(&env) {
            return Err(QuickexError::ContractPaused);
        }
        escrow::resolve_dispute(&env, caller, commitment, resolve_for_owner, recipient)
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
        admin::initialize(&env, admin)
    }

    /// Get the stored contract schema version.
    ///
    /// Returns `0` for legacy deployments created before version tracking existed.
    pub fn get_version(env: Env) -> u32 {
        admin::get_version(&env)
    }

    /// Run any pending data migrations for the current contract code (**Admin only**).
    ///
    /// This entrypoint is intended to be called immediately after upgrading the contract WASM
    /// whenever the new release introduces storage or schema changes.
    pub fn migrate(env: Env, caller: Address) -> Result<u32, QuickexError> {
        admin::migrate(&env, &caller)
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
        admin::set_paused(&env, caller, new_state)
    }

    /// Check if the function is currently paused.
    ///
    /// Returns `true` if paused, `false` otherwise.
    pub fn is_feature_paused(env: &Env, flag: PauseFlag) -> bool {
        storage::is_feature_paused(env, flag)
    }

    /// Pause a function in the contract (**Admin only**).
    ///
    /// When paused, the particular operations is blocked. Caller must equal the stored admin.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `caller` - Caller address (must equal admin)
    /// * `mask` - PauseFlag Enum
    ///
    /// # Errors
    /// * `Unauthorized` - Caller is not the admin, or admin not set
    pub fn pause_features(env: Env, caller: Address, mask: u64) -> Result<(), QuickexError> {
        admin::set_pause_flags(&env, &caller, mask, 0)
    }

    /// UnPause a function in the contract (**Admin only**).
    ///
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `caller` - Caller address (must equal admin)
    /// * `mask` - PauseFlag Enum
    ///
    /// # Errors
    /// * `Unauthorized` - Caller is not the admin, or admin not set
    pub fn unpause_features(env: Env, caller: Address, mask: u64) -> Result<(), QuickexError> {
        admin::set_pause_flags(&env, &caller, 0, mask)
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
        admin::set_admin(&env, caller, new_admin)
    }

    /// Check if the contract is currently paused.
    ///
    /// Returns `true` if paused, `false` otherwise.
    pub fn is_paused(env: Env) -> bool {
        admin::is_paused(&env)
    }

    /// Get the current admin address.
    ///
    /// Returns `None` if the contract has not been initialized.
    pub fn get_admin(env: Env) -> Option<Address> {
        admin::get_admin(&env)
    }

    /// Get the current fee configuration (read-only).
    pub fn get_fee_config(env: Env) -> FeeConfig {
        storage::get_fee_config(&env)
    }

    /// Set the fee configuration (**Admin only**).
    pub fn set_fee_config(
        env: Env,
        caller: Address,
        config: FeeConfig,
    ) -> Result<(), QuickexError> {
        admin::set_fee_config(&env, &caller, config)
    }

    /// Get the platform wallet address (read-only).
    pub fn get_platform_wallet(env: Env) -> Option<Address> {
        storage::get_platform_wallet(&env)
    }

    /// Set the platform wallet address (**Admin only**).
    pub fn set_platform_wallet(
        env: Env,
        caller: Address,
        wallet: Address,
    ) -> Result<(), QuickexError> {
        admin::set_platform_wallet(&env, &caller, wallet)
    }

    /// Get the status of an escrow by its commitment hash (read-only).
    ///
    /// Returns `Pending`, `Spent`, `Expired`, or `Refunded` if an escrow exists; `None` otherwise.
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
    /// escrow exists with status `Pending`, matching amount, and not yet expired.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `amount` - Amount to verify (non-negative)
    /// * `salt` - Salt used when creating the deposit
    /// * `owner` - Owner of the escrow
    pub fn verify_proof_view(env: Env, amount: i128, salt: Bytes, owner: Address) -> bool {
        let commitment_result = commitment::amount_commitment_hashes(&env, &owner, amount, &salt);

        let (commitment, legacy_commitment) = match commitment_result {
            Ok(c) => c,
            Err(_) => return false,
        };

        let commitment_bytes: Bytes = commitment.into();
        let entry: Option<EscrowEntry> = get_escrow(&env, &commitment_bytes).or_else(|| {
            let legacy_commitment_bytes: Bytes = legacy_commitment.into();
            get_escrow(&env, &legacy_commitment_bytes)
        });

        match entry {
            Some(e) => {
                if e.status != EscrowStatus::Pending {
                    return false;
                }
                if e.expires_at > 0 && env.ledger().timestamp() >= e.expires_at {
                    return false;
                }
                e.amount == amount
            }
            None => false,
        }
    }

    /// Get a privacy-aware view of escrow details for a commitment hash (read-only).
    ///
    /// Returns a [`PrivacyAwareEscrowView`] if an escrow exists for the commitment,
    /// or `None` otherwise.
    ///
    /// ## Privacy behaviour
    /// - If the escrow owner **has privacy enabled** and `caller` is **not** the owner,
    ///   the `amount`, `owner`, and `arbiter` fields are returned as `None`.
    /// - If privacy is **disabled**, or `caller` equals the escrow owner,
    ///   all fields are returned in full.
    /// - If `caller` equals the arbiter, the arbiter field is always visible.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `commitment` - 32-byte commitment hash identifying the escrow
    /// * `caller` - Address of the caller; used to determine whether full details
    ///   are returned when privacy is enabled
    pub fn get_escrow_details(
        env: Env,
        commitment: BytesN<32>,
        caller: Address,
    ) -> Option<PrivacyAwareEscrowView> {
        let commitment_bytes: Bytes = commitment.into();
        let entry = get_escrow(&env, &commitment_bytes)?;

        let privacy_on = privacy::get_privacy(&env, entry.owner.clone());
        let is_owner = caller == entry.owner;
        let is_arbiter = entry.arbiter.as_ref().is_some_and(|a| caller == *a);
        let show_sensitive = !privacy_on || is_owner || is_arbiter;

        if show_sensitive {
            Some(PrivacyAwareEscrowView {
                token: entry.token,
                amount: Some(entry.amount),
                owner: Some(entry.owner),
                status: entry.status,
                created_at: entry.created_at,
                expires_at: entry.expires_at,
                arbiter: entry.arbiter,
            })
        } else {
            Some(PrivacyAwareEscrowView {
                token: entry.token,
                amount: None,
                owner: None,
                status: entry.status,
                created_at: entry.created_at,
                expires_at: entry.expires_at,
                arbiter: None,
            })
        }
    }

    // -----------------------------------------------------------------------
    // Stealth Address – Privacy v2 (Issue #157)
    // -----------------------------------------------------------------------

    /// Register an ephemeral public key and lock funds for a stealth recipient.
    ///
    /// The sender computes a one-time `stealth_address` off-chain via:
    /// ```text
    /// shared_secret   = SHA-256(eph_pub || spend_pub)
    /// stealth_address = SHA-256(spend_pub || shared_secret)
    /// ```
    /// The contract re-derives and verifies the stealth address on-chain, then
    /// locks `amount` of `token` under it.  The recipient's main address is
    /// never recorded on-chain.
    ///
    /// All deposit parameters are bundled in [`StealthDepositParams`] to keep
    /// the argument count within clippy's limit.
    ///
    /// # Errors
    /// * `InvalidAmount`            – amount ≤ 0.
    /// * `ContractPaused`           – contract is paused.
    /// * `StealthAddressMismatch`   – on-chain re-derivation does not match.
    /// * `StealthAddressAlreadyUsed`– stealth address already has a deposit.
    pub fn register_ephemeral_key(
        env: Env,
        params: StealthDepositParams,
    ) -> Result<BytesN<32>, QuickexError> {
        if admin::is_paused(&env) {
            return Err(QuickexError::ContractPaused);
        }
        if is_feature_paused(&env, PauseFlag::Deposit) {
            return Err(QuickexError::OperationPaused);
        }
        stealth::register_ephemeral_key(&env, params)
    }

    /// Withdraw funds locked under a stealth address.
    ///
    /// The caller proves ownership by supplying the matching `spend_pub` and
    /// `eph_pub`.  The contract re-derives the stealth address; if it matches,
    /// funds are transferred to `recipient`.
    ///
    /// The `recipient` address is only revealed at withdrawal time and is not
    /// linked to any prior on-chain activity.
    ///
    /// # Arguments
    /// * `recipient`       – Address to receive the funds (must authorize).
    /// * `eph_pub`         – Ephemeral public key from the registration event.
    /// * `spend_pub`       – Recipient's spend public key (32 bytes).
    /// * `stealth_address` – The one-time stealth address to withdraw from.
    ///
    /// # Errors
    /// * `StealthEscrowNotFound`  – no escrow for this stealth address.
    /// * `AlreadySpent`           – already withdrawn or refunded.
    /// * `EscrowExpired`          – escrow has passed its expiry.
    /// * `StealthAddressMismatch` – re-derived address does not match.
    /// * `ContractPaused`         – contract is paused.
    pub fn stealth_withdraw(
        env: Env,
        recipient: Address,
        eph_pub: BytesN<32>,
        spend_pub: BytesN<32>,
        stealth_address: BytesN<32>,
    ) -> Result<bool, QuickexError> {
        if admin::is_paused(&env) {
            return Err(QuickexError::ContractPaused);
        }
        if is_feature_paused(&env, PauseFlag::Withdrawal) {
            return Err(QuickexError::OperationPaused);
        }
        stealth::stealth_withdraw(&env, recipient, eph_pub, spend_pub, stealth_address)
    }

    /// Get the status of a stealth escrow (read-only).
    ///
    /// Returns `Pending`, `Spent`, or `Refunded` if an escrow exists; `None` otherwise.
    /// Does not reveal amount, token, or any key material.
    ///
    /// # Arguments
    /// * `stealth_address` – The 32-byte one-time stealth address.
    pub fn get_stealth_status(env: Env, stealth_address: BytesN<32>) -> Option<EscrowStatus> {
        stealth::get_stealth_status(&env, &stealth_address)
    }

    /// Upgrade the contract to a new WASM implementation (**Admin only**).
    ///
    /// Caller must have the [`Role::Admin`] role and authorize.
    /// The new WASM must be pre-uploaded to the network.
    /// Emits an upgrade event for audit.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `caller` - Caller address (must have admin role; must authorize)
    /// * `new_wasm_hash` - 32-byte hash of the new WASM code
    ///
    /// # Errors
    /// * `Unauthorized` - Caller is not the admin, or admin not set
    ///
    /// # Security
    /// Updates the contract's executable code. Call [`migrate`](QuickexContract::migrate)
    /// afterwards if the new release requires storage migration.
    pub fn upgrade(
        env: Env,
        caller: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), QuickexError> {
        admin::require_admin(&env, &caller)?;

        env.deployer()
            .update_current_contract_wasm(new_wasm_hash.clone());

        events::publish_contract_upgraded(&env, new_wasm_hash, &caller);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Role Management (**Admin only**)
    // -----------------------------------------------------------------------

    /// Grant a role to an account.
    pub fn grant_role(
        env: Env,
        caller: Address,
        target: Address,
        role: Role,
    ) -> Result<(), QuickexError> {
        admin::grant_role(&env, caller, target, role)
    }

    /// Revoke a role from an account.
    pub fn revoke_role(
        env: Env,
        caller: Address,
        target: Address,
        role: Role,
    ) -> Result<(), QuickexError> {
        admin::revoke_role(&env, caller, target, role)
    }

    /// Get all roles assigned to an account.
    pub fn get_roles(env: Env, account: Address) -> Vec<Role> {
        storage::get_roles(&env, &account)
    }
}
