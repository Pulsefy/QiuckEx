import { Injectable, Logger, ForbiddenException } from '@nestjs/common';
import { AppConfigService } from '../config';
import { SupabaseService } from '../supabase/supabase.service';
import { SorobanEventIndexerService } from '../ingestion/soroban-event-indexer.service';
import { IndexerCheckpointRepository } from '../ingestion/indexer-checkpoint.repository';
import { MetricsService } from '../metrics/metrics.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class TestnetResetService {
  private readonly logger = new Logger(TestnetResetService.name);

  constructor(
    private readonly config: AppConfigService,
    private readonly supabase: SupabaseService,
    private readonly indexer: SorobanEventIndexerService,
    private readonly checkpointRepo: IndexerCheckpointRepository,
    private readonly metrics: MetricsService,
    private readonly audit: AuditService,
  ) {}

  async resetAndReindex(
    actor: string,
    contractId: string,
    fromLedger: number,
    toLedger: number,
    force = true,
  ) {
    if (!this.config.isTestnet) {
      this.logger.warn('Attempt to run testnet reset in non-testnet environment');
      throw new ForbiddenException('Reset can only be executed on testnet');
    }

    this.logger.log(`Starting testnet reset for contract=${contractId} ledgers=[${fromLedger},${toLedger}] by ${actor}`);
    await this.audit.log(actor, 'testnet_reset_started', contractId, { fromLedger, toLedger });

    const client = this.supabase.getClient();

    const deletes: Array<Promise<{ count?: number | null }>> = [];

    // Delete domain event rows in ledger range
    try {
      deletes.push(
        client.from('escrow_events').delete().gte('ledger_sequence', fromLedger).lte('ledger_sequence', toLedger),
      );
      deletes.push(
        client.from('privacy_events').delete().gte('ledger_sequence', fromLedger).lte('ledger_sequence', toLedger),
      );
      deletes.push(
        client.from('admin_events').delete().gte('ledger_sequence', fromLedger).lte('ledger_sequence', toLedger),
      );
      deletes.push(
        client.from('stealth_events').delete().gte('ledger_sequence', fromLedger).lte('ledger_sequence', toLedger),
      );

      // Unparsed events scoped by ledger
      deletes.push(
        client.from('unparsed_soroban_events').delete().gte('ledger', fromLedger).lte('ledger', toLedger),
      );

      // Clear checkpoints for this contract
      deletes.push(client.from('indexer_checkpoints').delete().eq('contract_id', contractId));

      const results = await Promise.all(deletes);

      const counts = results.map((r) => ({ deleted: r?.count ?? null }));

      this.logger.log(`Deleted rows: ${JSON.stringify(counts)}`);
      await this.audit.log(actor, 'testnet_reset_deleted_rows', contractId, { counts });
      this.metrics?.recordError?.call(this.metrics, 'testnet_reset', 'deleted_rows');
    } catch (err) {
      this.logger.error(`Failed to delete testnet rows: ${(err as Error).message}`);
      await this.audit.log(actor, 'testnet_reset_delete_failed', contractId, { error: (err as Error).message });
      throw err;
    }

    // Reinitialize checkpoint to before fromLedger
    try {
      const initialCheckpoint = Math.max(0, fromLedger - 1);
      await this.checkpointRepo.saveLastLedger(contractId, initialCheckpoint);
      this.logger.log(`Set checkpoint for ${contractId} to ${initialCheckpoint}`);
      await this.audit.log(actor, 'testnet_reset_checkpoint_reset', contractId, { checkpoint: initialCheckpoint });
    } catch (err) {
      this.logger.error(`Failed to reset checkpoint: ${(err as Error).message}`);
      await this.audit.log(actor, 'testnet_reset_checkpoint_failed', contractId, { error: (err as Error).message });
      throw err;
    }

    // Run deterministic reindex
    let indexResult;
    try {
      indexResult = await this.indexer.indexLedgerRange(contractId, fromLedger, toLedger, undefined, force);
      this.logger.log(`Reindex result: ${JSON.stringify(indexResult)}`);
      await this.audit.log(actor, 'testnet_reset_reindexed', contractId, { indexResult });
      // Record metric as an error counter for visibility if dedicated metric not present
      try {
        this.metrics?.recordExternalCall?.call(this.metrics, 'testnet_reset', 'reindex', 1);
      } catch {}
    } catch (err) {
      this.logger.error(`Reindex failed: ${(err as Error).message}`);
      await this.audit.log(actor, 'testnet_reset_reindex_failed', contractId, { error: (err as Error).message });
      throw err;
    }

    await this.audit.log(actor, 'testnet_reset_completed', contractId, { indexResult });

    return {
      contractId,
      fromLedger,
      toLedger,
      deletedCounts: counts,
      indexResult,
    };
  }
}
