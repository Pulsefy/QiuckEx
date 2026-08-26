/**
 * Receipt metadata repository port.
 *
 * Defines the persistence contract for indexer/database-backed receipt
 * metadata. `ReceiptsService` depends on the `ReceiptMetadataRepository`
 * interface (via the `RECEIPT_METADATA_REPOSITORY` DI token) rather than on a
 * concrete storage implementation, so unit tests can substitute an in-memory
 * fake without touching Supabase.
 *
 * The Supabase-backed adapter lives in the same file as the concrete
 * `SupabaseReceiptMetadataRepository`.
 */

import { Injectable, Logger } from '@nestjs/common';

import { SupabaseService } from '../supabase/supabase.service';

export interface IndexerMetadata {
  txHash: string;
  submittedAt: string;
  network: 'testnet' | 'mainnet';
}

// ---------------------------------------------------------------------------
// Port
// ---------------------------------------------------------------------------

export interface ReceiptMetadataRepository {
  /**
   * Fetch indexer metadata for a transaction. Implementations must degrade
   * gracefully to sensible defaults when the tx is not yet indexed (e.g. a
   * new submission).
   */
  getIndexerMetadata(
    txHash: string,
    network: 'testnet' | 'mainnet',
  ): Promise<IndexerMetadata>;
}

export const RECEIPT_METADATA_REPOSITORY = Symbol(
  'RECEIPT_METADATA_REPOSITORY',
);

// ---------------------------------------------------------------------------
// Supabase adapter
// ---------------------------------------------------------------------------

@Injectable()
export class SupabaseReceiptMetadataRepository
  implements ReceiptMetadataRepository
{
  private readonly logger = new Logger(SupabaseReceiptMetadataRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  async getIndexerMetadata(
    txHash: string,
    network: 'testnet' | 'mainnet',
  ): Promise<IndexerMetadata> {
    const defaults: IndexerMetadata = {
      txHash,
      submittedAt: new Date().toISOString(),
      network,
    };

    // Best-effort lookup against the indexer `receipts` table. The table may
    // not exist in all environments; fall back to defaults if so.
    try {
      const { data, error } = await this.supabase
        .getClient()
        .from('receipts')
        .select('*')
        .eq('tx_hash', txHash)
        .maybeSingle();

      if (error) {
        this.logger.debug(
          `receipts lookup failed for ${txHash}: ${error.message}`,
        );
        return defaults;
      }

      if (!data) return defaults;

      return {
        txHash,
        submittedAt: String(data.created_at ?? defaults.submittedAt),
        network,
      };
    } catch (err) {
      this.logger.debug(
        `receipts lookup threw for ${txHash}: ${(err as Error).message}`,
      );
      return defaults;
    }
  }
}
