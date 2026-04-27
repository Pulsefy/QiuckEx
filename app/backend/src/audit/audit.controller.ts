import { Controller, Get, Query, Res, Delete } from '@nestjs/common';
import { AuditService } from './audit.service';
import { QueryAuditLogsDto } from './audit.model';
import { Response } from 'express';

@Controller('admin/audit')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  // Admin endpoint to query logs with filters and pagination
  @Get()
  queryLogs(@Query() query: QueryAuditLogsDto) {
    // In a real app, this route would be protected by an AdminGuard
    return this.auditService.query(query);
  }

  // Export capability (CSV)
  @Get('export')
  exportCsv(@Res() res: Response) {
    const csv = this.auditService.exportCsv();
    res.header('Content-Type', 'text/csv');
    res.attachment('audit-logs.csv');
    return res.send(csv);
  }

  // Manual trigger for retention strategy (could also be a cron job)
  @Delete('retention')
  applyRetentionStrategy() {
    // Defaulting to 90 days retention policy
    return this.auditService.applyRetention(90);
  }
}
