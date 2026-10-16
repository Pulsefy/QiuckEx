import { Controller, Get, Query, Res, Delete, UseGuards } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiProduces, ApiTags } from '@nestjs/swagger';
import { AuditService } from './audit.service';
import { ApplyRetentionResponseDto, QueryAuditLogsDto, QueryAuditLogsResponseDto } from './audit.model';
import { Response } from 'express';
import { RateLimitTier } from '../auth/decorators/rate-limit-group.decorator';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';

@ApiTags('admin/audit')
@Controller('admin/audit')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get()
  @UseGuards(ApiKeyGuard)
  @RequireScopes('admin')
  @RateLimitTier("public-read")
  @ApiOperation({ summary: 'Query audit logs' })
  @ApiOkResponse({
    description: 'Paginated list of audit logs',
    type: QueryAuditLogsResponseDto,
  })
  queryLogs(@Query() query: QueryAuditLogsDto): Promise<QueryAuditLogsResponseDto> {
    return this.auditService.query(query);
  }

  @Get('export')
  @UseGuards(ApiKeyGuard)
  @RequireScopes('admin')
  @RateLimitTier("export")
  @ApiOperation({ summary: 'Export audit logs as CSV' })
  @ApiProduces('text/csv')
  @ApiOkResponse({
    description: 'CSV file download of audit logs',
    schema: {
      type: 'string',
      format: 'binary',
    },
  })
  async exportCsv(@Res() res: Response) {
    const csv = await this.auditService.exportCsv();
    res.header('Content-Type', 'text/csv');
    res.attachment('audit-logs.csv');
    return res.send(csv);
  }

  @Delete('retention')
  @UseGuards(ApiKeyGuard)
  @RequireScopes('admin')
  @RateLimitTier("mutation")
  @ApiOperation({ summary: 'Apply retention strategy to purge old audit logs' })
  @ApiOkResponse({
    description: 'Retention purge results',
    type: ApplyRetentionResponseDto,
  })
  applyRetentionStrategy(): Promise<ApplyRetentionResponseDto> {
    return this.auditService.applyRetention(90);
  }
}

