/**
 * Receipt v3 Type Definitions — MOB-41
 * Enhanced metadata for support/debugging and contributor validation
 */

export type ReceiptStatus = 'pending' | 'success' | 'failed' | 'refund';

export type TimelineStepStatus = 'completed' | 'current' | 'upcoming' | 'failed';

export interface TimelineEvent {
  id: string;
  step: 'created' | 'submitted' | 'validated' | 'executed' | 'settled' | 'refunded';
  title: string;
  description: string;
  timestamp: string;
  status: TimelineStepStatus;
  txHash?: string;
}

export interface ReceiptMetadata {
  receiptHash: string;
  createdAt: string;
  expiresAt?: string;
}

export interface ContractMetadata {
  contractId: string;
  wasmHash: string;
  deployedAt: string;
  networkPassphrase: string;
}

export interface NetworkMetadata {
  network: 'mainnet' | 'testnet' | 'futurenet';
  horizonUrl: string;
  ledger: number;
  ledgerCloseTime: string;
}

export interface ShareableReceipt {
  title: string;
  amount: string;
  asset: string;
  status: ReceiptStatus;
  receiptHash: string;
  contractId: string;
  network: string;
  explorerUrl: string;
  supportText: string;
}

export interface ReceiptData {
  id: string;
  amount: string;
  asset: string;
  sender: string;
  recipient: string;
  memo?: string;
  status: ReceiptStatus;
  metadata: ReceiptMetadata;
  contract: ContractMetadata;
  network: NetworkMetadata;
  timeline: TimelineEvent[];
}