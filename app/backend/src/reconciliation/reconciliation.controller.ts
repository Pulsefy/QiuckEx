import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  ConflictException,
  Param,
  Post,
  Query,
} from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';

import { ReconciliationWorkerService } from './reconciliation-worker.service';
import { BackfillService, BackfillConfig, BackfillProgress, BackfillResult } from './backfill.service';
import { AutoMatchService } from './auto-match.service';
import { UnmatchedQueueRepository } from './unmatched-queue.repository';
import { ReconciliationReport } from './types/reconciliation.types';
import type { IncomingTransaction, MatchResult } from './types/auto-match.types';

/**
 * Admin endpoints for the reconciliation worker and auto-match engine.
 * These should be protected by an API-key guard in production.
 */
@ApiTags('reconciliation')
@Controller('reconciliation')
export class ReconciliationController {
  constructor(
    private readonly worker: ReconciliationWorkerService,
    private readonly backfill: BackfillService,
    private readonly autoMatch: AutoMatchService,
    private readonly unmatchedQueue: UnmatchedQueueRepository,
  ) {}

  // ─── Existing reconciliation endpoints ──────────────────────────────────────

  @Get('status')
  @ApiOperation({ summary: 'Return the status and last report of the reconciliation worker' })
  @ApiResponse({ status: 200, description: 'Current worker status' })
  getStatus() {
    return {
      running: this.worker.running,
      lastReport: this.worker.getLastReport(),
    };
  }

  @Post('trigger')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Manually trigger a reconciliation run (admin only)' })
  @ApiResponse({ status: 200, description: 'Reconciliation run completed' })
  @ApiResponse({ status: 409, description: 'A run is already in progress' })
  async trigger(): Promise<ReconciliationReport> {
    try {
      return await this.worker.triggerManually();
    } catch (err) {
      if ((err as Error).message === 'Reconciliation is already running') {
        throw new ConflictException('A reconciliation run is already in progress');
      }
      throw err;
    }
  }

  @Post('backfill')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Trigger a backfill job for a ledger range (admin only)' })
  @ApiResponse({ status: 200, description: 'Backfill job completed' })
  @ApiResponse({ status: 409, description: 'A backfill job is already running' })
  async startBackfill(@Body() config: BackfillConfig): Promise<BackfillResult> {
    try {
      return await this.backfill.startBackfill(config);
    } catch (err) {
      if ((err as Error).message === 'A backfill job is already running') {
        throw new ConflictException('A backfill job is already running');
      }
      throw err;
    }
  }

  @Get('backfill/status')
  @ApiOperation({ summary: 'Get the current backfill job progress' })
  @ApiResponse({ status: 200, description: 'Backfill progress' })
  getBackfillStatus(): BackfillProgress | null {
    return this.backfill.getBackfillProgress();
  }

  // ─── Auto-match endpoints ────────────────────────────────────────────────────

  @Get('auto-match/status')
  @ApiOperation({ summary: 'Return the current status of the auto-match engine' })
  @ApiResponse({ status: 200, description: 'Auto-match engine status' })
  getAutoMatchStatus() {
    return { running: this.autoMatch.running };
  }

  @Post('auto-match/trigger')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Manually trigger an auto-match cycle (admin only)' })
  @ApiResponse({ status: 200, description: 'Cycle summary counters' })
  @ApiResponse({ status: 409, description: 'A cycle is already running' })
  async triggerAutoMatch(): Promise<{
    processed: number;
    matched: number;
    queued: number;
    unmatched: number;
  }> {
    if (this.autoMatch.running) {
      throw new ConflictException('An auto-match cycle is already in progress');
    }
    return this.autoMatch.runAutoMatchCycle();
  }

  /**
   * Process a single transaction through the matching algorithm on demand.
   * Useful for replaying a specific transaction or testing the scoring logic.
   */
  @Post('auto-match/process')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Score and process a single transaction on demand (admin only)' })
  @ApiResponse({ status: 200, description: 'Match result for the supplied transaction' })
  async processTransaction(@Body() tx: IncomingTransaction): Promise<MatchResult> {
    return this.autoMatch.processTransaction(tx);
  }

  // ─── Unmatched transactions queue ────────────────────────────────────────────

  @Get('unmatched')
  @ApiOperation({ summary: 'List pending unmatched transactions awaiting manual review' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Max rows (1–100, default 20)' })
  @ApiQuery({ name: 'offset', required: false, type: Number, description: 'Zero-based row offset (default 0)' })
  @ApiResponse({ status: 200, description: 'Paginated list of unmatched transactions' })
  async listUnmatched(
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
  ) {
    const parsedLimit = Math.min(100, Math.max(1, parseInt(limit ?? '20', 10) || 20));
    const parsedOffset = Math.max(0, parseInt(offset ?? '0', 10) || 0);
    return this.unmatchedQueue.listPending(parsedLimit, parsedOffset);
  }

  @Get('unmatched/:id')
  @ApiOperation({ summary: 'Get a single unmatched transaction by ID' })
  @ApiResponse({ status: 200, description: 'Unmatched transaction details' })
  @ApiResponse({ status: 404, description: 'Not found' })
  async getUnmatched(@Param('id') id: string) {
    const record = await this.unmatchedQueue.findById(id);
    if (!record) {
      throw new NotFoundException(`Unmatched transaction ${id} not found`);
    }
    return record;
  }

  /**
   * Resolve an unmatched transaction after manual operator review.
   * The body should include the `resolvedBy` public key and an optional note.
   */
  @Post('unmatched/:id/resolve')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Manually resolve an unmatched transaction (operator only)' })
  @ApiResponse({ status: 200, description: 'Transaction marked as resolved' })
  @ApiResponse({ status: 404, description: 'Not found' })
  async resolveUnmatched(
    @Param('id') id: string,
    @Body() body: { resolvedBy: string; note?: string },
  ) {
    const record = await this.unmatchedQueue.findById(id);
    if (!record) {
      throw new NotFoundException(`Unmatched transaction ${id} not found`);
    }
    await this.unmatchedQueue.resolve(id, body.resolvedBy, body.note);
    return { id, status: 'resolved' };
  }

  /**
   * Dismiss an unmatched transaction — the operator has determined it is not
   * related to any QuickEx payment link and requires no further action.
   */
  @Delete('unmatched/:id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Dismiss an unmatched transaction (operator only)' })
  @ApiResponse({ status: 200, description: 'Transaction dismissed' })
  @ApiResponse({ status: 404, description: 'Not found' })
  async dismissUnmatched(
    @Param('id') id: string,
    @Body() body: { resolvedBy: string; note?: string },
  ) {
    const record = await this.unmatchedQueue.findById(id);
    if (!record) {
      throw new NotFoundException(`Unmatched transaction ${id} not found`);
    }
    await this.unmatchedQueue.dismiss(id, body.resolvedBy, body.note);
    return { id, status: 'dismissed' };
  }
}
