/**
 * Mirrors TransactionItemDto from the backend.
 * Keep in sync with app/backend/src/transactions/dto/transaction.dto.ts
 */
export interface TransactionItem {
  amount: string;
  asset: string;
  memo?: string;
  timestamp: string;
  txHash: string;
  pagingToken: string;
  source: string;
  destination: string;
  status: "Success" | "Pending";
}

/**
 * Mirrors TransactionResponseDto from the backend.
 */
export interface TransactionResponse {
  items: TransactionItem[];
  nextCursor?: string;
}

/**
 * Transaction-related types for receipt metadata
 */

export interface StellarTransaction {
  id: string;
  pagingToken: string;
  successful: boolean;
  hash: string;
  ledger: number;
  createdAt: string;
  sourceAccount: string;
  sourceAccountSequence: string;
  feeCharged: string;
  maxFee: string;
  operationCount: number;
  memoType?: string;
  memo?: string;
  signatures: string[];
}

export interface SorobanContractEvent {
  id: string;
  type: string;
  ledger: number;
  timestamp: string;
  contractId: string;
  topic: string[];
  value: Record<string, unknown>;
}

export interface HorizonLink {
  href: string;
  templated?: boolean;
}
