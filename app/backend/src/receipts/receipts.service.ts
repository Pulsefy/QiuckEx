/**
 * ReceiptsService
 *
 * Orchestrates calls to Horizon, Soroban RPC, and the indexer/database,
 * then hands raw data to ReceiptNormalizer to produce a stable receipt.
 *
 * Location: app/backend/src/receipts/receipts.service.ts
 */

import {
  Injectable,
  Logger,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ReceiptNormalizer,
  HorizonOperation,
  HorizonTransaction,
  SorobanRpcResult,
  IndexerMetadata,
} from './normalizers/receipt.normalizer';
import { NormalizedReceipt } from './schemas/receipt.schema';
import { GetReceiptByTxDto, GetReceiptsByAddressDto } from './dto/receipt.dto';

@Injectable()
export class ReceiptsService {
  private readonly logger = new Logger(ReceiptsService.name);
  private readonly horizonUrl: string;
  private readonly sorobanRpcUrl: string;

  constructor(
    private readonly normalizer: ReceiptNormalizer,
    private readonly config: ConfigService,
  ) {
    const network = this.config.get<string>('STELLAR_NETWORK', 'testnet');
    this.horizonUrl =
      network === 'mainnet'
        ? 'https://horizon.stellar.org'
        : 'https://horizon-testnet.stellar.org';
    this.sorobanRpcUrl =
      network === 'mainnet'
        ? 'https://mainnet.stellar.validationcloud.io/v1/soroban/rpc'
        : 'https://soroban-testnet.stellar.org';
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  async getByTxHash(dto: GetReceiptByTxDto): Promise<NormalizedReceipt> {
    const { txHash, operationIndex = 0 } = dto;

    const [tx, operations] = await Promise.all([
      this.fetchTransaction(txHash),
      this.fetchOperations(txHash),
    ]);

    if (!tx) throw new NotFoundException(`Transaction ${txHash} not found`);

    const op = operations[operationIndex];
    if (!op) {
      throw new BadRequestException(
        `No operation at index ${operationIndex} for tx ${txHash}`,
      );
    }

    const soroban = op.type === 'invoke_host_function'
      ? await this.fetchSorobanResult(txHash)
      : null;

    const indexer = await this.fetchIndexerMetadata(txHash);

    return this.normalizer.normalize(op, tx, soroban, indexer);
  }

  async getByAddress(dto: GetReceiptsByAddressDto): Promise<{
    receipts: NormalizedReceipt[];
    nextCursor: string | null;
    total: number;
  }> {
    const { address, type, status, limit = 20, cursor } = dto;

    const rawOps = await this.fetchOperationsByAddress(address, limit, cursor);
    const txHashes = [...new Set(rawOps.map((o) => o.transaction_hash))];

    const results = await Promise.allSettled(
      txHashes.map((hash) => this.getByTxHash({ txHash: hash })),
    );

    let receipts = results
      .filter((r): r is PromiseFulfilledResult<NormalizedReceipt> => r.status === 'fulfilled')
      .map((r) => r.value);

    // Log any that failed so we don't silently swallow errors
    results
      .filter((r) => r.status === 'rejected')
      .forEach((r) =>
        this.logger.warn(`Receipt normalization failed: ${(r as PromiseRejectedResult).reason}`),
      );

    // Apply optional client-side filters (indexer should do this too, but
    // keeping filters here ensures correctness during reindexing)
    if (type) receipts = receipts.filter((r) => r.type === type);
    if (status) receipts = receipts.filter((r) => r.status === status);

    return {
      receipts,
      nextCursor: rawOps.length === limit ? rawOps[rawOps.length - 1].paging_token : null,
      total: receipts.length,
    };
  }

  // ── Data fetchers ─────────────────────────────────────────────────────────

  private async fetchTransaction(txHash: string): Promise<HorizonTransaction | null> {
    try {
      const res = await fetch(`${this.horizonUrl}/transactions/${txHash}`);
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`Horizon tx fetch failed: ${res.status}`);
      return res.json();
    } catch (err) {
      this.logger.error(`fetchTransaction(${txHash}): ${err}`);
      throw err;
    }
  }

  private async fetchOperations(txHash: string): Promise<HorizonOperation[]> {
    try {
      const res = await fetch(
        `${this.horizonUrl}/transactions/${txHash}/operations`,
      );
      if (!res.ok) throw new Error(`Horizon operations fetch failed: ${res.status}`);
      const json = await res.json();
      return json._embedded?.records ?? [];
    } catch (err) {
      this.logger.error(`fetchOperations(${txHash}): ${err}`);
      throw err;
    }
  }

  private async fetchOperationsByAddress(
    address: string,
    limit: number,
    cursor?: string,
  ): Promise<HorizonOperation[]> {
    const params = new URLSearchParams({
      limit: String(limit),
      order: 'desc',
    });
    if (cursor) params.set('cursor', cursor);

    const res = await fetch(
      `${this.horizonUrl}/accounts/${address}/operations?${params}`,
    );
    if (!res.ok) throw new Error(`Horizon account ops fetch failed: ${res.status}`);
    const json = await res.json();
    return json._embedded?.records ?? [];
  }

  private async fetchSorobanResult(txHash: string): Promise<SorobanRpcResult | null> {
    try {
      const res = await fetch(this.sorobanRpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'getTransaction',
          params: { hash: txHash },
        }),
      });

      if (!res.ok) return null;
      const json = await res.json();
      const rpcResult = json.result;

      if (!rpcResult || rpcResult.status === 'NOT_FOUND') {
        return { status: 'NOT_FOUND', txHash };
      }

      return {
        status: rpcResult.status,
        txHash,
        contractId: rpcResult.contractId,
        functionName: rpcResult.functionName,
        args: rpcResult.args,
        returnValue: rpcResult.returnValue,
        cpuInstructions: rpcResult.resultMetaXdr
          ? undefined  // Would decode XDR here in production
          : undefined,
        errorCode: rpcResult.errorCode,
        errorMessage: rpcResult.errorMessage,
        resourceFee: rpcResult.feeCharged,
      };
    } catch (err) {
      this.logger.warn(`fetchSorobanResult(${txHash}): ${err}. Proceeding without Soroban data.`);
      return null;
    }
  }

  /**
   * Fetches from the QuickEx indexer/database.
   * Falls back to defaults if the tx isn't yet indexed (e.g. new submission).
   */
  private async fetchIndexerMetadata(txHash: string): Promise<IndexerMetadata> {
    // TODO: replace with actual Supabase/database call
    // e.g. await this.supabase.from('receipts').select('*').eq('tx_hash', txHash).single()
    const network = this.config.get<'testnet' | 'mainnet'>('STELLAR_NETWORK', 'testnet');
    return {
      txHash,
      submittedAt: new Date().toISOString(),
      network,
    };
  }
}