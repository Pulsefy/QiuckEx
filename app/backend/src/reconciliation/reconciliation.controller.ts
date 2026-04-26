import {
  Controller,
  Get,
  Post,
  HttpCode,
  HttpStatus,
  ConflictException,
  Body,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

import { ReconciliationWorkerService } from './reconciliation-worker.service';
import { BackfillService, BackfillConfig, BackfillProgress, BackfillResult } from './backfill.service';
import { ReconciliationReport } from './types/reconciliation.types';

/**
 * Admin endpoints for the reconciliation worker.
 * These should be protected by an API-key guard in production.
 */
@ApiTags('reconciliation')
@Controller('reconciliation')
export class ReconciliationController {
  constructor(
    private readonly worker: ReconciliationWorkerService,
    private readonly backfill: BackfillService,
  ) {}

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
}
