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
}

/**
 * Mirrors TransactionResponseDto from the backend.
 */
export interface TransactionResponse {
  items: TransactionItem[];
  nextCursor?: string;
}
