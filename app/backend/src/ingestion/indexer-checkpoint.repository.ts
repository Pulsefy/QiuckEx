import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";

/**
 * Persists and reads the highest fully-processed ledger per contract.
 * Used by the batch poller to resume without re-scanning indexed ranges.
 */
@Injectable()
export class IndexerCheckpointRepository {
  private readonly logger = new Logger(IndexerCheckpointRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  async getLastLedger(contractId: string): Promise<number | null> {
    const { data, error } = await this.supabase.getClient()
      .from("indexer_checkpoints")
      .select("last_ledger")
      .eq("contract_id", contractId)
      .maybeSingle();

    if (error) {
      this.logger.error(`Failed to read checkpoint for ${contractId}: ${error.message}`);
      throw error;
    }
    return data ? Number(data.last_ledger) : null;
  }

  async saveLastLedger(contractId: string, ledger: number): Promise<void> {
    const { error } = await this.supabase.getClient()
      .from("indexer_checkpoints")
      .upsert(
        { contract_id: contractId, last_ledger: ledger, updated_at: new Date().toISOString() },
        { onConflict: "contract_id" },
      );

    if (error) {
      this.logger.error(`Failed to save checkpoint for ${contractId}: ${error.message}`);
      throw error;
    }
  }
}
