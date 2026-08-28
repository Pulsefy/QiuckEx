import { Controller, Get, Query, Res, Delete } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { AuditService } from './audit.service';
import { QueryAuditLogsDto } from './audit.model';
import { Response } from 'express';

@ApiTags('audit')
@Controller('admin/audit')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  /**
   * Query audit logs with optional filters and pagination.
   *
   * Feature-flag changes include a `metadata.flagAuditEntry` field with the
   * shape: `{ flagKey, previousValue, newValue, actor, ip, userAgent }`.
   */
  @Get()
  @ApiOperation({
    summary: 'Query admin audit logs',
    description:
      'Returns a paginated list of audit log entries. ' +
      'Filter by `action=feature_flag.updated` to see feature-flag changes. ' +
      'Each feature-flag entry includes `metadata.flagAuditEntry` with full ' +
      'actor attribution (API key id or X-Admin-Actor header), client ip, and userAgent.',
  })
  queryLogs(@Query() query: QueryAuditLogsDto) {
    // In a real app, this route would be protected by an AdminGuard
    return this.auditService.query(query);
  }

  // Export capability (CSV)
  @Get('export')
  @ApiOperation({ summary: 'Export audit logs as CSV' })
  async exportCsv(@Res() res: Response) {
    const csv = await this.auditService.exportCsv();
    res.header('Content-Type', 'text/csv');
    res.attachment('audit-logs.csv');
    return res.send(csv);
  }

  // Manual trigger for retention strategy (could also be a cron job)
  @Delete('retention')
  @ApiOperation({ summary: 'Apply audit log retention policy (default: 90 days)' })
  applyRetentionStrategy() {
    // Defaulting to 90 days retention policy
    return this.auditService.applyRetention(90);
  }
}
