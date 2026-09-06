import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { NormalizedReceipt } from './schemas/receipt.schema';

export const RECEIPTS_REPOSITORY = 'RECEIPTS_REPOSITORY';

export interface ReceiptsRepository {
  save(receipt: NormalizedReceipt, network: string): Promise<void>;
  findByTxHash(
    txHash: string,
    operationIndex?: number,
    network?: string,
  ): Promise<NormalizedReceipt | null>;
}

@Injectable()
export class SupabaseReceiptsRepository implements ReceiptsRepository {
  private readonly logger = new Logger(SupabaseReceiptsRepository.name);
  private readonly supabase: SupabaseClient;

  constructor(config: ConfigService) {
    const url = config.get<string>('SUPABASE_URL', '');
    const key = config.get<string>('SUPABASE_SERVICE_ROLE_KEY', '');
    if (!url || !key) {
      throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set');
    }
    this.supabase = createClient(url, key);
  }

  async save(receipt: NormalizedReceipt, network: string): Promise<void> {
    const record = {
      tx_hash: receipt.txHash,
      operation_index: receipt.operationIndex ?? 0,
      network,
      receipt,
      updated_at: new Date().toISOString(),
    };

    const { error } = await this.supabase
      .from('receipts')
      .upsert(record, { onConflict: 'tx_hash,operation_index,network' });

    if (error) {
      this.logger.error(`Failed to save receipt: ${error.message}`);
      throw error;
    }
  }

  async findByTxHash(
    txHash: string,
    operationIndex = 0,
    network?: string,
  ): Promise<NormalizedReceipt | null> {
    let query = this.supabase
      .from('receipts')
      .select('receipt')
      .eq('tx_hash', txHash)
      .eq('operation_index', operationIndex);

    if (network) {
      query = query.eq('network', network);
    }

    const { data, error } = await query.maybeSingle();

    if (error) {
      this.logger.error(`Failed to fetch receipt: ${error.message}`);
      throw error;
    }

    return data ? (data.receipt as NormalizedReceipt) : null;
  }
}