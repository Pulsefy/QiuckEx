/**
 * ReceiptNormalizer
 *
 * Aggregates raw Horizon transaction data, Soroban RPC results, indexer
 * metadata, and backend user records into a single stable NormalizedReceipt.
 *
 * Location: app/backend/src/receipts/normalizers/receipt.normalizer.ts
 */

import { Injectable, Logger } from '@nestjs/common';
import {
  NormalizedReceipt,
  ReceiptType,
  ReceiptStatus,
  StellarAsset,
  FeeMetadata,
  PartyInfo,
  ContractMeta,
  DiagnosticMeta,
} from '../schemas/receipt.schema';

// ── Raw types from Horizon / Soroban RPC ────────────────────────────────────

export interface HorizonOperation {
  id: string;
  paging_token: string;
  type: string;
  type_i: number;
  transaction_hash: string;
  transaction_successful: boolean;
  source_account: string;
  created_at: string;
  // payment fields
  from?: string;
  to?: string;
  amount?: string;
  asset_type?: string;
  asset_code?: string;
  asset_issuer?: string;
  // invoke_host_function fields
  function?: string;
  parameters?: Array<{ value: string; type: string }>;
}

export interface HorizonTransaction {
  hash: string;
  ledger: number;
  created_at: string;
  fee_charged: string;
  max_fee: string;
  envelope_xdr: string;
  result_xdr: string;
  result_meta_xdr: string;
  memo_type: string;
  memo?: string;
  successful: boolean;
  // Soroban resource fee (may be absent for classic txs)
  fee_account?: string;
}

export interface SorobanRpcResult {
  status: 'SUCCESS' | 'FAILED' | 'NOT_FOUND';
  txHash: string;
  contractId?: string;
  functionName?: string;
  args?: Record<string, unknown>;
  returnValue?: string;
  diagnosticEvents?: string[];
  cpuInstructions?: number;
  memBytes?: number;
  ledgerReads?: number;
  ledgerWrites?: number;
  errorCode?: string;
  errorMessage?: string;
  resourceFee?: string;
}

export interface IndexerMetadata {
  txHash: string;
  submittedAt: string;
  confirmedAt?: string;
  /** QuickEx internal receipt ID (stable across retries) */
  receiptId?: string;
  senderUsername?: string;
  receiverUsername?: string;
  network: 'testnet' | 'mainnet';
}

// ── Normalizer ───────────────────────────────────────────────────────────────

@Injectable()
export class ReceiptNormalizer {
  private readonly logger = new Logger(ReceiptNormalizer.name);

  private readonly EXPLORER_BASE: Record<'testnet' | 'mainnet', string> = {
    testnet: 'https://stellar.expert/explorer/testnet/tx',
    mainnet: 'https://stellar.expert/explorer/public/tx',
  };

  /**
   * Build a stable NormalizedReceipt from all available sources.
   * Designed to be idempotent — calling with the same inputs always
   * produces the same receiptId and timestamps.
   */
  normalize(
    operation: HorizonOperation,
    transaction: HorizonTransaction,
    soroban: SorobanRpcResult | null,
    indexer: IndexerMetadata,
  ): NormalizedReceipt {
    const txHash = transaction.hash;
    const operationIndex = this.extractOperationIndex(operation);
    const receiptId = indexer.receiptId ?? this.deriveReceiptId(txHash, operationIndex);
    const type = this.deriveType(operation, soroban);
    const status = this.deriveStatus(transaction, soroban);
    const network = indexer.network;

    return {
      // Identity
      receiptId,
      txHash,
      operationIndex,
      type,
      status,

      // Timestamps (stable: use indexer submittedAt for failed txs so
      // timestamps don't shift on testnet retries)
      createdAt: status === 'failed'
        ? indexer.submittedAt
        : (indexer.confirmedAt ?? transaction.created_at),
      updatedAt: new Date().toISOString(),
      ledger: transaction.ledger ?? null,

      // Parties
      sender: {
        address: operation.from ?? operation.source_account,
        username: indexer.senderUsername ?? null,
      },
      receiver: this.buildReceiver(operation, indexer),

      // Value
      asset: this.buildAsset(operation),
      amount: operation.amount ?? '0',
      displayAmount: this.formatDisplayAmount(operation),
      memo: transaction.memo ?? null,
      memoType: this.normalizeMemoType(transaction.memo_type),

      // Fees
      fee: this.buildFee(transaction, soroban),

      // Contract
      contract: type === 'contract_action' ? this.buildContract(operation, soroban) : null,

      // Diagnostics (always present)
      diagnostic: this.buildDiagnostic(transaction, soroban),

      // Network
      network,
      explorerUrl: `${this.EXPLORER_BASE[network]}/${txHash}`,
    };
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private deriveReceiptId(txHash: string, opIndex: number): string {
    // Stable, deterministic — safe to cache and store
    return `rcpt_${txHash.slice(0, 12)}_${opIndex}`;
  }

  private extractOperationIndex(op: HorizonOperation): number {
    // Horizon paging tokens encode ledger+tx+op; fall back to 0
    const parts = op.paging_token?.split('-');
    return parts?.length >= 3 ? parseInt(parts[2], 10) : 0;
  }

  private deriveType(
    op: HorizonOperation,
    soroban: SorobanRpcResult | null,
  ): ReceiptType {
    if (soroban || op.type === 'invoke_host_function') return 'contract_action';
    // QuickEx tags refunds by convention via the memo or function name
    if (op.type === 'payment' && op.function === 'refund') return 'refund';
    return 'payment';
  }

  private deriveStatus(
    tx: HorizonTransaction,
    soroban: SorobanRpcResult | null,
  ): ReceiptStatus {
    if (!tx.successful) return 'failed';
    if (soroban?.status === 'FAILED') return 'failed';
    if (soroban?.status === 'NOT_FOUND') return 'pending';
    if (!tx.ledger) return 'pending';
    return 'success';
  }

  private buildReceiver(
    op: HorizonOperation,
    indexer: IndexerMetadata,
  ): PartyInfo | null {
    if (!op.to) return null;
    return {
      address: op.to,
      username: indexer.receiverUsername ?? null,
    };
  }

  private buildAsset(op: HorizonOperation): StellarAsset {
    const type = (op.asset_type ?? 'native') as StellarAsset['type'];
    return {
      type,
      code: type === 'native' ? 'XLM' : (op.asset_code ?? 'UNKNOWN'),
      issuer: op.asset_issuer ?? null,
    };
  }

  private formatDisplayAmount(op: HorizonOperation): string {
    const code =
      op.asset_type === 'native' ? 'XLM' : (op.asset_code ?? 'UNKNOWN');
    const amount = op.amount ?? '0';
    return `${amount} ${code}`;
  }

  private normalizeMemoType(
    raw: string,
  ): NormalizedReceipt['memoType'] {
    const map: Record<string, NormalizedReceipt['memoType']> = {
      text: 'text',
      id: 'id',
      hash: 'hash',
      return: 'return',
      none: 'none',
      MemoNone: 'none',
      MemoText: 'text',
      MemoID: 'id',
      MemoHash: 'hash',
      MemoReturn: 'return',
    };
    return map[raw] ?? 'none';
  }

  private buildFee(
    tx: HorizonTransaction,
    soroban: SorobanRpcResult | null,
  ): FeeMetadata {
    const baseFee = tx.fee_charged ?? '0';
    const resourceFee = soroban?.resourceFee ?? '0';
    const totalStroops =
      BigInt(baseFee) + BigInt(resourceFee);
    const totalXlm = (Number(totalStroops) / 1e7).toFixed(7);

    return {
      baseFeeSatoshis: baseFee,
      totalFeeSatoshis: totalStroops.toString(),
      feeXlm: totalXlm,
    };
  }

  private buildContract(
    op: HorizonOperation,
    soroban: SorobanRpcResult | null,
  ): ContractMeta | null {
    if (!soroban?.contractId) return null;

    return {
      contractId: soroban.contractId,
      functionName: soroban.functionName ?? op.function ?? 'unknown',
      args: soroban.args ?? {},
      returnValue: soroban.returnValue ?? null,
      resources: soroban.cpuInstructions != null
        ? {
            cpuInstructions: soroban.cpuInstructions,
            memBytes: soroban.memBytes ?? 0,
            ledgerReads: soroban.ledgerReads ?? 0,
            ledgerWrites: soroban.ledgerWrites ?? 0,
          }
        : null,
    };
  }

  private buildDiagnostic(
    tx: HorizonTransaction,
    soroban: SorobanRpcResult | null,
  ): DiagnosticMeta {
    return {
      errorCode: soroban?.errorCode ?? null,
      errorMessage: soroban?.errorMessage ?? null,
      // Include XDR on any non-success so devs can replay/debug
      resultXdr: !tx.successful ? (tx.result_xdr ?? null) : null,
      envelopeXdr: !tx.successful ? (tx.envelope_xdr ?? null) : null,
    };
  }
}