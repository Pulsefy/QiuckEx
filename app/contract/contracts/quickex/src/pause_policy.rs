//! Pause Policy v1 – centralized gating for global pause, granular flags, and emergency mode.
//!
//! Emergency mode blocks risky state transitions while keeping fund-recovery paths
//! (withdraw, refund, stealth withdraw) and neutral maintenance (cleanup, TTL extension) usable.

use crate::admin;
use crate::errors::QuickexError;
use crate::storage::{self, PauseFlag};
use soroban_sdk::{contracttype, Env};

/// Reason recorded in pause-related admin events.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PauseChangeReason {
    GlobalPause = 1,
    GlobalUnpause = 2,
    FeatureFlagsUpdated = 3,
    EmergencyActivated = 4,
}

/// Contract entry points subject to pause policy enforcement.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum EntryPoint {
    Deposit = 1,
    DepositWithCommitment = 2,
    DepositPartial = 3,
    PartialPayment = 4,
    Withdraw = 5,
    Refund = 6,
    StealthDeposit = 7,
    StealthWithdraw = 8,
    Dispute = 9,
    ResolveDispute = 10,
    VoteForDispute = 11,
    ResolveDisputeMultiSig = 12,
    SetPrivacy = 13,
    CleanupEscrow = 14,
    ExtendEscrowTtl = 15,
}

impl EntryPoint {
    /// Granular pause flag associated with this entry point, if any.
    pub fn pause_flag(self) -> Option<PauseFlag> {
        match self {
            EntryPoint::Deposit
            | EntryPoint::DepositPartial
            | EntryPoint::PartialPayment
            | EntryPoint::StealthDeposit => Some(PauseFlag::Deposit),
            EntryPoint::DepositWithCommitment => Some(PauseFlag::DepositWithCommitment),
            EntryPoint::Withdraw | EntryPoint::StealthWithdraw => Some(PauseFlag::Withdrawal),
            EntryPoint::Refund => Some(PauseFlag::Refund),
            EntryPoint::SetPrivacy => Some(PauseFlag::SetPrivacy),
            EntryPoint::Dispute
            | EntryPoint::ResolveDispute
            | EntryPoint::VoteForDispute
            | EntryPoint::ResolveDisputeMultiSig
            | EntryPoint::CleanupEscrow
            | EntryPoint::ExtendEscrowTtl => None,
        }
    }

    /// Whether this entry point is on the emergency-mode allowlist.
    pub fn is_emergency_safe(self) -> bool {
        matches!(
            self,
            EntryPoint::Withdraw
                | EntryPoint::Refund
                | EntryPoint::StealthWithdraw
                | EntryPoint::CleanupEscrow
                | EntryPoint::ExtendEscrowTtl
        )
    }
}

/// Returns `true` when the entry point may execute during emergency mode.
pub fn is_emergency_allowlisted(entry: EntryPoint) -> bool {
    entry.is_emergency_safe()
}

/// Enforce pause policy for a state-changing entry point.
pub fn require_entry_allowed(env: &Env, entry: EntryPoint) -> Result<(), QuickexError> {
    if storage::is_emergency_mode(env) {
        if entry.is_emergency_safe() {
            return Ok(());
        }
        return Err(QuickexError::ContractPaused);
    }

    if admin::is_paused(env) {
        return Err(QuickexError::ContractPaused);
    }

    if let Some(flag) = entry.pause_flag() {
        if storage::is_feature_paused(env, flag) {
            return Err(QuickexError::OperationPaused);
        }
    }

    Ok(())
}

/// Block privileged admin/config mutations while emergency mode is active.
pub fn require_admin_entry_allowed(env: &Env) -> Result<(), QuickexError> {
    if storage::is_emergency_mode(env) {
        return Err(QuickexError::ContractPaused);
    }
    Ok(())
}
