/**
 * Domain types for QuickEx Soroban contract events.
 * These mirror the Rust event structs defined in contracts/quickex/src/events.rs
 */

export type SorobanEventType =
  | "EscrowDeposited"
  | "EscrowWithdrawn"
  | "EscrowRefunded"
  | "PrivacyToggled"
  | "ContractPaused"
  | "AdminChanged"
  | "ContractUpgraded";

export interface BaseContractEvent {
  eventType: SorobanEventType;
  txHash: string;
  ledgerSequence: number;
  pagingToken: string;
  contractTimestamp: bigint;
}

export interface EscrowDepositedEvent extends BaseContractEvent {
  eventType: "EscrowDeposited";
  commitment: string; // hex
  owner: string;
  token: string;
  amount: bigint;
  expiresAt: bigint;
}

export interface EscrowWithdrawnEvent extends BaseContractEvent {
  eventType: "EscrowWithdrawn";
  commitment: string;
  owner: string;
  token: string;
  amount: bigint;
}

export interface EscrowRefundedEvent extends BaseContractEvent {
  eventType: "EscrowRefunded";
  commitment: string;
  owner: string;
  token: string;
  amount: bigint;
}

export interface PrivacyToggledEvent extends BaseContractEvent {
  eventType: "PrivacyToggled";
  owner: string;
  enabled: boolean;
}

export interface ContractPausedEvent extends BaseContractEvent {
  eventType: "ContractPaused";
  admin: string;
  paused: boolean;
}

export interface AdminChangedEvent extends BaseContractEvent {
  eventType: "AdminChanged";
  oldAdmin: string;
  newAdmin: string;
}

export interface ContractUpgradedEvent extends BaseContractEvent {
  eventType: "ContractUpgraded";
  newWasmHash: string;
  admin: string;
}

export type QuickExContractEvent =
  | EscrowDepositedEvent
  | EscrowWithdrawnEvent
  | EscrowRefundedEvent
  | PrivacyToggledEvent
  | ContractPausedEvent
  | AdminChangedEvent
  | ContractUpgradedEvent;

export type EscrowEvent =
  | EscrowDepositedEvent
  | EscrowWithdrawnEvent
  | EscrowRefundedEvent;
