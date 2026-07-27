import {
  Controller,
  Get,
  Post,
  HttpCode,
  HttpStatus,
  ConflictException,
  Body,
  Query,
  Res,
  NotFoundException,
} from '@nestjs/common';
import { Response } from 'express';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

import { ReconciliationWorkerService } from './reconciliation-worker.service';
import { BackfillService, BackfillConfig, BackfillProgress, BackfillResult } from './backfill.service';
import { ReconciliationReport } from './types/reconciliation.types';
import { AppConfigService } from '../config/app-config.service';

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
    private readonly config: AppConfigService,
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

  @Get('export')
  @ApiOperation({ summary: 'Export the last RC validation report' })
  @ApiResponse({ status: 200, description: 'Exported report in JSON or Markdown' })
  exportReport(
    @Query('format') format: 'json' | 'markdown',
    @Res() res: Response
  ) {
    const report = this.worker.getLastReport();
    if (!report) {
      throw new ConflictException('No RC validation report available yet. Please trigger a run first.');
    }

    const requestedFormat = format === 'markdown' ? 'markdown' : 'json';
    const timestamp = new Date().toISOString();
    
    const escrowsIrreconcilable = report.escrows.results.filter((r) => r.irreconcilable);
    const paymentsIrreconcilable = report.payments.results.filter((r) => r.irreconcilable);
    const blockers = [
      ...escrowsIrreconcilable.map(r => `Escrow ${r.id}: ${r.irreconcilableReason}`),
      ...paymentsIrreconcilable.map(r => `Payment ${r.id}: ${r.irreconcilableReason}`)
    ];

    const exportData = {
      runId: report.runId,
      timestamps: {
        startedAt: report.startedAt,
        completedAt: report.completedAt,
        exportedAt: timestamp
      },
      environment: {
        network: this.config.network || 'unknown',
      },
      blockers,
      summary: {
        escrows: {
          processed: report.escrows.processed,
          irreconcilable: report.escrows.irreconcilable
        },
        payments: {
          processed: report.payments.processed,
          irreconcilable: report.payments.irreconcilable
        },
        discrepancyAlert: report.alert || null
      }
    };

    if (requestedFormat === 'markdown') {
      const markdown = `
# Release Candidate Validation Report

**Run ID**: \`${exportData.runId}\`
**Network**: \`${exportData.environment.network}\`
**Exported At**: ${exportData.timestamps.exportedAt}
**Validation Started**: ${exportData.timestamps.startedAt}
**Validation Completed**: ${exportData.timestamps.completedAt}

## Summary
- **Escrows**: ${exportData.summary.escrows.processed} processed, ${exportData.summary.escrows.irreconcilable} irreconcilable
- **Payments**: ${exportData.summary.payments.processed} processed, ${exportData.summary.payments.irreconcilable} irreconcilable

${exportData.summary.discrepancyAlert ? \`## 🚨 Discrepancy Alert
**Severity**: ${exportData.summary.discrepancyAlert.severity}
**Message**: ${exportData.summary.discrepancyAlert.message}
**Details**: ${exportData.summary.discrepancyAlert.details}
\` : '✅ No discrepancy alerts.'}

## Blockers (${exportData.blockers.length})
${exportData.blockers.length === 0 ? '- None' : exportData.blockers.map(b => \`- ${b}\`).join('\\n')}
      `.trim();

      res.setHeader('Content-Type', 'text/markdown');
      res.setHeader('Content-Disposition', \`attachment; filename="rc-report-${report.runId}.md"\`);
      return res.send(markdown);
    }

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', \`attachment; filename="rc-report-${report.runId}.json"\`);
    return res.json(exportData);
  }
}
