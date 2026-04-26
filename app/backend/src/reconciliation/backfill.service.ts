import { Injectable, Logger } from '@nestjs/common';
import { Horizon } from 'stellar-sdk';
import { v4 as uuidv4 } from 'uuid';

import { AppConfigService } from '../config/app-config.service';
import { SupabaseService } from '../supabase/supabase.service';
import { MetricsService } from '../metrics/metrics.service';
import { SorobanEventParser } from '../ingestion/soroban-event.parser';
import { EscrowEventRepository } from '../ingestion/escrow-event.repository';
import { CursorRepository } from '../ingestion/cursor.repository';
import type { RawHorizonContractEvent } from '../ingestion/soroban-event.parser';
import type { EscrowEvent, QuickExContractEvent } from '../ingestion/types/contract-event.types';

export interface BackfillConfig {
  startLedger: number;
  endLedger: number;
  contractId: string;
  batchSize?: number;
}

export interface BackfillProgress {
  runId: string;
  status: 'running' | 'completed' | 'failed';
  startLedger: number;
  endLedger: number;
  currentLedger: number;
  processedCount: number;
  errorCount: number;
  startedAt: string;
  completedAt?: string;
  errorMessage?: string;
}

export interface BackfillResult {
  runId: string;
  startLedger: number;
  endLedger: number;
  processedCount: number;
  errorCount: number;
  durationMs: number;
  success: boolean;
}

/**
 * BackfillService processes historical ledger ranges to fill gaps in event ingestion.
 * 
 * Features:
 * - Idempotent: Can be run repeatedly without duplicating data
 * - Batch processing: Processes ledgers in configurable batch sizes
 * - Progress tracking: Provides real-time progress updates
 * - Error handling: Continues processing on individual ledger failures
 * - Metrics: Records backfill performance metrics
 */
@Injectable()
export class BackfillService {
  private readonly logger = new Logger(BackfillService.name);
  private readonly server: Horizon.Server;
  private activeBackfill: BackfillProgress | null = null;

  constructor(
    private readonly config: AppConfigService,
    private readonly supabase: SupabaseService,
    private readonly metrics: MetricsService,
    private readonly parser: SorobanEventParser,
    private readonly escrowRepo: EscrowEventRepository,
    private readonly cursorRepo: CursorRepository,
  ) {
    const horizonUrl =
      config.network === 'mainnet'
        ? 'https://horizon.stellar.org'
        : 'https://horizon-testnet.stellar.org';

    this.server = new Horizon.Server(horizonUrl);
    this.logger.log(
      `BackfillService initialized against ${config.network} (${horizonUrl})`,
    );
  }

  /**
   * Start a backfill job for the specified ledger range.
   * Only one backfill can run at a time.
   */
  async startBackfill(config: BackfillConfig): Promise<BackfillResult> {
    if (this.activeBackfill) {
      throw new Error('A backfill job is already running');
    }

    const runId = uuidv4();
    const startTime = Date.now();
    const batchSize = config.batchSize || 200;

    this.activeBackfill = {
      runId,
      status: 'running',
      startLedger: config.startLedger,
      endLedger: config.endLedger,
      currentLedger: config.startLedger,
      processedCount: 0,
      errorCount: 0,
      startedAt: new Date().toISOString(),
    };

    this.logger.log(
      `[${runId}] Starting backfill: ledger ${config.startLedger} to ${config.endLedger}`,
    );

    try {
      await this.processLedgerRange(
        config.contractId,
        config.startLedger,
        config.endLedger,
        batchSize,
        runId,
      );

      const durationMs = Date.now() - startTime;
      const result: BackfillResult = {
        runId,
        startLedger: config.startLedger,
        endLedger: config.endLedger,
        processedCount: this.activeBackfill.processedCount,
        errorCount: this.activeBackfill.errorCount,
        durationMs,
        success: true,
      };

      this.activeBackfill.status = 'completed';
      this.activeBackfill.completedAt = new Date().toISOString();
      this.logger.log(
        `[${runId}] Backfill completed: ${this.activeBackfill.processedCount} processed, ${this.activeBackfill.errorCount} errors in ${durationMs}ms`,
      );

      this.activeBackfill = null;
      return result;
    } catch (error) {
      const durationMs = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);

      this.activeBackfill.status = 'failed';
      this.activeBackfill.completedAt = new Date().toISOString();
      this.activeBackfill.errorMessage = errorMessage;

      this.logger.error(
        `[${runId}] Backfill failed after ${durationMs}ms: ${errorMessage}`,
      );

      this.metrics.recordError('backfill', 'processing_error');

      const result: BackfillResult = {
        runId,
        startLedger: config.startLedger,
        endLedger: config.endLedger,
        processedCount: this.activeBackfill.processedCount,
        errorCount: this.activeBackfill.errorCount,
        durationMs,
        success: false,
      };

      this.activeBackfill = null;
      return result;
    }
  }

  /**
   * Get the current backfill progress if one is running.
   */
  getBackfillProgress(): BackfillProgress | null {
    return this.activeBackfill;
  }

  /**
   * Process a range of ledgers in batches.
   */
  private async processLedgerRange(
    contractId: string,
    startLedger: number,
    endLedger: number,
    batchSize: number,
    runId: string,
  ): Promise<void> {
    let currentLedger = startLedger;

    while (currentLedger <= endLedger) {
      const batchEnd = Math.min(currentLedger + batchSize - 1, endLedger);

      this.logger.debug(
        `[${runId}] Processing batch: ledger ${currentLedger} to ${batchEnd}`,
      );

      try {
        await this.processBatch(contractId, currentLedger, batchEnd, runId);
        this.activeBackfill!.currentLedger = batchEnd;
      } catch (error) {
        this.activeBackfill!.errorCount++;
        this.logger.error(
          `[${runId}] Batch failed (ledger ${currentLedger}-${batchEnd}): ${error instanceof Error ? error.message : String(error)}`,
        );
        // Continue to next batch despite error
      }

      currentLedger = batchEnd + 1;
    }
  }

  /**
   * Process a single batch of ledgers.
   */
  private async processBatch(
    contractId: string,
    startLedger: number,
    endLedger: number,
    runId: string,
  ): Promise<void> {
    const startTime = Date.now();

    try {
      // Fetch contract events for the ledger range
      const events = await this.fetchContractEvents(
        contractId,
        startLedger,
        endLedger,
      );

      const duration = (Date.now() - startTime) / 1000;
      this.metrics.recordExternalCall('horizon', 'fetchContractEvents', duration);

      // Process each event
      for (const rawEvent of events) {
        try {
          await this.processEvent(rawEvent, contractId, runId);
          this.activeBackfill!.processedCount++;
        } catch (error) {
          this.activeBackfill!.errorCount++;
          this.logger.warn(
            `[${runId}] Event processing failed: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      }

      this.logger.debug(
        `[${runId}] Batch complete: ${events.length} events processed`,
      );
    } catch (error) {
      const duration = (Date.now() - startTime) / 1000;
      this.metrics.recordExternalCall('horizon', 'fetchContractEvents', duration);
      const errorType = error instanceof Error ? error.constructor.name : 'UnknownError';
      this.metrics.recordError('horizon', errorType);
      throw error;
    }
  }

  /**
   * Fetch contract events from Horizon for a ledger range.
   */
  private async fetchContractEvents(
    contractId: string,
    startLedger: number,
    endLedger: number,
  ): Promise<RawHorizonContractEvent[]> {
    const url = new URL(
      `${this.server.serverURL}/contract_events`,
    );
    url.searchParams.set('contract_id', contractId);
    url.searchParams.set('min_ledger', startLedger.toString());
    url.searchParams.set('max_ledger', endLedger.toString());
    url.searchParams.set('limit', '200');

    const response = await fetch(url.toString());
    if (!response.ok) {
      throw new Error(
        `Horizon API error: ${response.status} ${response.statusText}`,
      );
    }

    const data = (await response.json()) as { _embedded: { records: RawHorizonContractEvent[] } };
    return data._embedded?.records || [];
  }

  /**
   * Process a single contract event.
   */
  private async processEvent(
    rawEvent: RawHorizonContractEvent,
    contractId: string,
    runId: string,
  ): Promise<void> {
    const event = this.parser.parse(rawEvent);

    if (!event) {
      // Unrecognised event, skip
      return;
    }

    this.logger.debug(
      `[${runId}] Processing event ${event.eventType} at ledger ${rawEvent.ledger}`,
    );

    // Persist event idempotently
    await this.persistEvent(event);

    // Update cursor to the latest ledger in this batch
    const streamId = `contract:${contractId}`;
    await this.cursorRepo.saveCursor(streamId, rawEvent.paging_token, rawEvent.ledger);
  }

  /**
   * Persist an event to the database.
   */
  private async persistEvent(event: QuickExContractEvent): Promise<void> {
    switch (event.eventType) {
      case 'EscrowDeposited':
      case 'EscrowWithdrawn':
      case 'EscrowRefunded':
        await this.escrowRepo.upsertEvent(event as EscrowEvent);
        break;
      default:
        // Other events are not persisted
        break;
    }
  }
}
