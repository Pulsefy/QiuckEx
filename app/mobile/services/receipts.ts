import { API_URL } from '../src/config/build';
import type { TransactionItem } from '../types/transaction';

/**
 * Base URL for the QuickEx backend.
 *
 * Resolved from the shared {@link API_URL} constant in `src/config/build`,
 * which is set at build time from app.config.ts and falls back to
 * `EXPO_PUBLIC_API_URL` or `http://localhost:4000` for local dev.
 */
const API_BASE_URL = API_URL;

/**
 * Normalized receipt response from the backend.
 * Mirrors the NormalizedReceipt schema from app/backend/src/receipts/schemas/receipt.schema.ts
 */
export interface NormalizedReceipt {
  receiptId: string;
  receiptHash: string;
  txHash: string;
  operationIndex: number;
  type: 'payment' | 'refund' | 'contract_action';
  status: 'success' | 'pending' | 'failed';
  receiptReference: string | null;
  createdAt: string;
  updatedAt: string;
  ledger: number | null;
  sender: {
    address: string;
    username: string | null;
  };
  receiver: {
    address: string | null;
    username: string | null;
  } | null;
  asset: {
    type: 'native' | 'credit_alphanum4' | 'credit_alphanum12';
    code: string;
    issuer: string | null;
  };
  amount: string;
  displayAmount: string;
  memo: string | null;
  memoType: 'text' | 'id' | 'hash' | 'return' | 'none';
  fee: {
    baseFeeSatoshis: string;
    totalFeeSatoshis: string;
    feeXlm: string;
  };
  contract: {
    contractId: string;
    functionName: string;
    args: Record<string, unknown>;
    returnValue: string | null;
    resources: {
      cpuInstructions: number;
      memBytes: number;
      ledgerReads: number;
      ledgerWrites: number;
    } | null;
    receiptReference?: string;
  } | null;
  diagnostic: {
    errorCode: string | null;
    errorMessage: string | null;
    resultXdr: string | null;
    envelopeXdr: string | null;
  };
  network: 'testnet' | 'mainnet';
  explorerUrl: string;
}

/**
 * Response wrapper from the receipts API.
 */
export interface ReceiptResponse {
  receipt: NormalizedReceipt;
}

/**
 * Maps a NormalizedReceipt from the backend to the mobile TransactionItem format.
 * This allows the receipt screen to display data from both cache and API consistently.
 */
function mapReceiptToTransactionItem(receipt: NormalizedReceipt): TransactionItem {
  const assetCode = receipt.asset.code || 'XLM';
  const assetIssuer = receipt.asset.issuer;
  const asset = assetIssuer ? `${assetCode}:${assetIssuer}` : assetCode;

  return {
    amount: receipt.amount,
    asset,
    memo: receipt.memo || undefined,
    timestamp: receipt.createdAt,
    txHash: receipt.txHash,
    pagingToken: receipt.receiptId,
    source: receipt.sender.address,
    destination: receipt.receiver?.address || '',
    status: receipt.status === 'success' ? 'Success' : receipt.status === 'pending' ? 'Pending' : 'Success',
  };
}

/**
 * Fetches a receipt by transaction hash from the QuickEx backend.
 * Throws a descriptive Error on network issues or non-2xx responses.
 *
 * @param txHash - The Stellar transaction hash
 * @param operationIndex - The operation index within the transaction (defaults to 0)
 * @returns A TransactionItem for the receipt
 */
export async function fetchReceiptByTxHash(
  txHash: string,
  operationIndex = 0,
): Promise<TransactionItem> {
  const params = new URLSearchParams({ operationIndex: String(operationIndex) });
  const url = `${API_BASE_URL}/v1/receipts/tx/${txHash}?${params.toString()}`;

  let response: Response;
  try {
    response = await fetch(url, {
      headers: { Accept: 'application/json' },
    });
  } catch (networkError) {
    throw new Error('Network request failed. Check your connection and try again.');
  }

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Receipt not found. The transaction may not exist or has not been indexed yet.');
    }
    let message = `Server error (${response.status})`;
    try {
      const body = (await response.json()) as { message?: string };
      if (body.message) message = body.message;
    } catch {
      // ignore JSON parse errors — keep the status-code message
    }
    throw new Error(message);
  }

  const data = (await response.json()) as ReceiptResponse;
  return mapReceiptToTransactionItem(data.receipt);
}

/**
 * Fetches receipts by Stellar address from the QuickEx backend.
 * Throws a descriptive Error on network issues or non-2xx responses.
 *
 * @param address - The Stellar public key
 * @param options - Optional query parameters (type, status, limit, cursor)
 * @returns An array of TransactionItems
 */
export async function fetchReceiptsByAddress(
  address: string,
  options: {
    type?: 'payment' | 'refund' | 'contract_action';
    status?: 'success' | 'pending' | 'failed';
    limit?: number;
    cursor?: string;
  } = {},
): Promise<{ receipts: TransactionItem[]; nextCursor: string | null; total: number }> {
  const { type, status, limit = 20, cursor } = options;

  const params = new URLSearchParams({ limit: String(limit) });
  if (type) params.set('type', type);
  if (status) params.set('status', status);
  if (cursor) params.set('cursor', cursor);

  const url = `${API_BASE_URL}/v1/receipts/address/${address}?${params.toString()}`;

  let response: Response;
  try {
    response = await fetch(url, {
      headers: { Accept: 'application/json' },
    });
  } catch (networkError) {
    throw new Error('Network request failed. Check your connection and try again.');
  }

  if (!response.ok) {
    let message = `Server error (${response.status})`;
    try {
      const body = (await response.json()) as { message?: string };
      if (body.message) message = body.message;
    } catch {
      // ignore JSON parse errors — keep the status-code message
    }
    throw new Error(message);
  }

  const data = (await response.json()) as {
    receipts: NormalizedReceipt[];
    nextCursor: string | null;
    total: number;
  };

  return {
    receipts: data.receipts.map(mapReceiptToTransactionItem),
    nextCursor: data.nextCursor,
    total: data.total,
  };
}
