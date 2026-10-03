use soroban_sdk::{contract, contracterror, contractimpl, log, Address, Env, Symbol, Vec};
use crate::admin::{self, Admin};
use crate::deposit::{self, Deposit};
use crate::dispute::{self, Dispute};
use crate::pause_policy::{self, EntryPoint, PausePolicy};
use crate::storage;

// --- Error Codes ---
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Error {
    /// Returned when the contract is paused or in emergency mode.
    ContractPaused = 0x0001,
    /// Returned when an operation is not authorized.
    Unauthorized = 0x0002,
    /// Returned when a dispute is not found.
    DisputeNotFound = 0x0003,
    /// Returned when the dispute is not in a state that allows resolution.
    InvalidDisputeState = 0x0004,
    /// Returned when the arbiter is not assigned to the dispute.
    NotArbiter = 0x0005,
    /// Returned when the resolution amount exceeds the dispute amount.
    AmountExceedsDispute = 0x0006,
}

// --- Data Structures ---

/// Represents the state of a dispute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisputeState {
    pub id: u64,
    pub depositor: Address,
    pub recipient: Address,
    pub amount: i128,
    pub status: DisputeStatus,
    pub arbiter: Option<Address>,
    pub resolved_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisputeStatus {
    Pending,
    Resolved,
}

// --- Contract Definition ---

#[contract]
pub struct QuickExContract;

// --- Admin Functions ---

#[contractimpl]
impl QuickExContract {
    /// Activates emergency mode, freezing all withdrawals and refunds indefinitely.
    /// This is distinct from the standard pause flag.
    pub fn activate_emergency_mode(env: Env, admin: Address) {
        admin::require_admin(&env, &admin);
        storage::set_emergency_mode(&env, true);
        log!(&env, "Emergency mode activated");
    }

    /// Deactivates emergency mode.
    pub fn deactivate_emergency_mode(env: Env, admin: Address) {
        admin::require_admin(&env, &admin);
        storage::set_emergency_mode(&env, false);
        log!(&env, "Emergency mode deactivated");
    }

    /// Checks if the contract is in emergency mode.
    pub fn is_emergency_mode(env: Env) -> bool {
        storage::is_emergency_mode(&env)
    }
}

// --- Deposit Functions ---

#[contractimpl]
impl QuickExContract {
    /// Deposits funds into the escrow.
    pub fn deposit(env: Env, depositor: Address, recipient: Address, amount: i128) {
        // Check emergency mode first
        if storage::is_emergency_mode(&env) {
            log!(&env, "Deposit rejected: Emergency mode active");
            panic!(Error::ContractPaused);
        }

        // Check standard pause policy
        pause_policy::require_entry_allowed(&env, EntryPoint::Deposit);

        // Logic to deposit funds...
        // For this implementation, we assume storage handles the escrow mapping.
        // In a real scenario, this would involve XLM/Asset transfers.
        log!(&env, "Deposit successful: {} from {} to {}", amount, depositor, recipient);
    }

    /// Deposits funds with a commitment hash.
    pub fn deposit_with_commitment(env: Env, depositor: Address, recipient: Address, amount: i128, commitment: [u8; 32]) {
        if storage::is_emergency_mode(&env) {
            log!(&env, "Deposit with commitment rejected: Emergency mode active");
            panic!(Error::ContractPaused);
        }

        pause_policy::require_entry_allowed(&env, EntryPoint::DepositWithCommitment);
        
        log!(&env, "Deposit with commitment successful");
    }

    /// Partial deposit.
    pub fn deposit_partial(env: Env, depositor: Address, recipient: Address, amount: i128) {
        if storage::is_emergency_mode(&env) {
            log!(&env, "Partial deposit rejected: Emergency mode active");
            panic!(Error::ContractPaused);
        }

        pause_policy::require_entry_allowed(&env, EntryPoint::DepositPartial);
        
        log!(&env, "Partial deposit successful");
    }
}

// --- Dispute Functions ---

#[contractimpl]
impl QuickExContract {
    /// Initiates a dispute.
    pub fn dispute(env: Env, caller: Address, dispute_id: u64) {
        // Check emergency mode
        if storage::is_emergency_mode(&env) {
            log!(&env, "Dispute initiation rejected: Emergency mode active");
            panic!(Error::ContractPaused);
        }

        pause_policy::require_entry_allowed(&env, EntryPoint::Dispute);

        // Logic to initiate dispute...
        log!(&env, "Dispute initiated: {}", dispute_id);
    }

    /// Resolves a dispute. This is the critical function that was missing the emergency mode check.
    /// 
    /// `resolve_for_owner`: If true, resolves in favor of the depositor (owner). If false, in favor of the recipient.
    pub fn resolve_dispute(env: Env, caller: Address, dispute_id: u64, resolve_for_owner: bool) {
        // FIX: Check emergency mode explicitly to prevent any fund movement during emergency halt.
        if storage::is_emergency_mode(&env) {
            log!(&env, "Resolve dispute rejected: Emergency mode active");
            panic!(Error::ContractPaused);
        }

        // Route through pause_policy for consistency with other gated entrypoints
        pause_policy::require_entry_allowed(&env, EntryPoint::ResolveDispute);

        // Verify caller is the assigned arbiter
        let dispute = storage::get_dispute(&env, dispute_id);
        
        match &dispute.arbiter {
            Some(arbiter) if arbiter == &caller => {},
            _ => panic!(Error::NotArbiter),
        }

        // Verify dispute is pending
        if dispute.status != DisputeStatus::Pending {
            panic!(Error::InvalidDisputeState);
        }

        // Resolve the dispute
        let recipient = if resolve_for_owner {
            dispute.depositor.clone()
        } else {
            dispute.recipient.clone()
        };

        // Transfer funds logic would go here
        log!(&env, "Dispute {} resolved for {}", dispute_id, recipient);

        // Update state
        storage::set_dispute(&env, dispute_id, DisputeState {
            id: dispute.id,
            depositor: dispute.depositor,
            recipient: dispute.recipient,
            amount: dispute.amount,
            status: DisputeStatus::Resolved,
            arbiter: dispute.arbiter,
            resolved_at: Some(env.ledger().sequence()),
        });
    }

    /// Resolves a dispute using multi-sig arbitration.
    pub fn resolve_dispute_multi_sig(env: Env, caller: Address, dispute_id: u64, resolve_for_owner: bool, signatures: Vec<Address>) {
        // FIX: Check emergency mode explicitly
        if storage::is_emergency_mode(&env) {
            log!(&env, "Resolve dispute multi-sig rejected: Emergency mode active");
            panic!(Error::ContractPaused);
        }

        pause_policy::require_entry_allowed(&env, EntryPoint::ResolveDisputeMultiSig);

        // Logic for multi-sig resolution...
        log!(&env, "Dispute {} resolved via multi-sig", dispute_id);
    }

    /// Resolves a dispute after a timeout period.
    pub fn resolve_dispute_timeout(env: Env, caller: Address, dispute_id: u64) {
        // FIX: Check emergency mode explicitly
        if storage::is_emergency_mode(&env) {
            log!(&env, "Resolve dispute timeout rejected: Emergency mode active");
            panic!(Error::ContractPaused);
        }

        pause_policy::require_entry_allowed(&env, EntryPoint::ResolveDisputeTimeout);

        // Logic for timeout resolution...
        log!(&env, "Dispute {} resolved via timeout", dispute_id);
    }
}

// --- Storage Helpers (Mocked for Structure) ---

mod storage {
    use soroban_sdk::{Address, Env, Symbol};
    use crate::lib::{DisputeState, DisputeStatus};

    pub fn set_emergency_mode(env: &Env, active: bool) {
        let key = Symbol::new(env, "emergency_mode");
        env.storage().persistent().set(&key, &active);
    }

    pub fn is_emergency_mode(env: &Env) -> bool {
        let key = Symbol::new(env, "emergency_mode");
        env.storage().persistent().get(&key).unwrap_or(false)
    }

    pub fn get_dispute(env: &Env, id: u64) -> DisputeState {
        let key = Symbol::new(env, &format!("dispute_{}", id));
        env.storage().persistent().get(&key).unwrap_or_else(|| {
            panic!("Dispute not found");
        })
    }

    pub fn set_dispute(env: &Env, id: u64, state: DisputeState) {
        let key = Symbol::new(env, &format!("dispute_{}", id));
        env.storage().persistent().set(&key, &state);
    }
}

// --- Admin Module ---

mod admin {
    use soroban_sdk::{Address, Env, Symbol};

    pub fn require_admin(env: &Env, admin: &Address) {
        let stored_admin: Address = env.storage().persistent().get(&Symbol::new(env, "admin")).unwrap();
        if *admin != stored_admin {
            panic!("Unauthorized");
        }
    }
}

// --- Pause Policy Module ---

mod pause_policy {
    use soroban_sdk::{Env, Symbol};
    use crate::lib::Error;

    pub enum EntryPoint {
        Deposit,
        DepositWithCommitment,
        DepositPartial,
        Dispute,
        ResolveDispute,
        ResolveDisputeMultiSig,
        ResolveDisputeTimeout,
    }

    pub fn require_entry_allowed(env: &Env, entry_point: EntryPoint) {
        // Check if the contract is paused via the standard pause flag
        let paused: bool = env.storage().persistent().get(&Symbol::new(env, "paused")).unwrap_or(false);
        if paused {
            panic!(Error::ContractPaused);
        }
        
        // Additional entry-point specific checks could go here
    }
}