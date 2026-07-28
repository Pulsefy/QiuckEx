/**
 * Canonical receipt schema for QuickEx
 * Covers payments, refunds, and Soroban contract actions.
 *
 * Location: app/backend/src/receipts/schemas/receipt.schema.ts
 */

export type ReceiptType = 'payment' | 'refund' | 'contract_action';

export type ReceiptStatus = 'success' | 'pending' | 'failed';

export type AssetType = 'native' | 'credit_alphanum4' | 'credit_alphanum12';

/** Stable, deterministic receipt ID derived from tx hash + operation index */
export interface ReceiptId {
  /** e.g. "rcpt_abc123_0" */
  id: string;
  txHash: string;
  operationIndex: number;
}

export interface StellarAsset {
  type: AssetType;
  code: string;
  /** null for XLM native */
  issuer: string | null;
}

export interface FeeMetadata {
  /** Base fee paid in stroops */
  baseFeeSatoshis: string;
  /** Total fee including resource fee for Soroban */
  totalFeeSatoshis: string;
  /** Human-readable XLM amount */
  feeXlm: string;
}

export interface PartyInfo {
  /** Stellar public key */
  address: string;
  /** QuickEx username if resolved */
  username: string | null;
}

export interface ContractMeta {
  contractId: string;
  functionName: string;
  /** Decoded arguments, best-effort */
  args: Record<string, unknown>;
  /** Raw return value from on-chain result */
  returnValue: string | null;
  /** Resource usage */
  resources: {
    cpuInstructions: number;
    memBytes: number;
    ledgerReads: number;
    ledgerWrites: number;
  } | null;
}

export interface DiagnosticMeta {
  /** Stellar error code string e.g. "op_no_destination" */
  errorCode: string | null;
  /** Human-readable description */
  errorMessage: string | null;
  /** Raw result XDR for debugging */
  resultXdr: string | null;
  /** Envelope XDR for replay */
  envelopeXdr: string | null;
}

/**
 * The single canonical receipt payload returned to all clients.
 * Clients can render receipt screens with no additional joins or calculations.
 */
export interface NormalizedReceipt {
  // ── Identity ─────────────────────────────────────────────────────────────
  receiptId: string;
  txHash: string;
  operationIndex: number;
  type: ReceiptType;
  status: ReceiptStatus;

  // ── Stable timestamps ────────────────────────────────────────────────────
  /** ISO-8601; ledger close time (success/pending) or submission time (failed) */
  createdAt: string;
  /** ISO-8601; when the receipt record was last updated */
  updatedAt: string;
  /** Stellar ledger sequence number; null if not yet closed */
  ledger: number | null;

  // ── Parties ──────────────────────────────────────────────────────────────
  sender: PartyInfo;
  receiver: PartyInfo | null;

  // ── Value ────────────────────────────────────────────────────────────────
  asset: StellarAsset;
  /** Exact amount string (no floating point) */
  amount: string;
  /** Pre-computed human display value e.g. "12.50 USDC" */
  displayAmount: string;
  /** Optional memo attached to the transaction */
  memo: string | null;
  memoType: 'text' | 'id' | 'hash' | 'return' | 'none';

  // ── Fees ─────────────────────────────────────────────────────────────────
  fee: FeeMetadata;

  // ── Contract (only for contract_action type) ─────────────────────────────
  contract: ContractMeta | null;

  // ── Diagnostics (always present; most fields null on success) ────────────
  diagnostic: DiagnosticMeta;

  // ── Network ──────────────────────────────────────────────────────────────
  network: 'testnet' | 'mainnet';
  /** Horizon/Soroban RPC explorer URL */
  explorerUrl: string;
}