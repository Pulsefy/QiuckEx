import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { CrashReportingService } from './crash-reporting.service';
import { CrashReportDto } from './dto/crash-report.dto';
import { RateLimitTier } from '../auth/decorators/rate-limit-group.decorator';

@ApiTags('Admin - Crash Reporting')
@Controller('admin/crash-reporting')
@UseGuards(ApiKeyGuard)
@RequireScopes('admin')
@ApiBearerAuth()
export class CrashReportingAdminController {
  constructor(private readonly crashReportingService: CrashReportingService) {}

  @Get('reports')
  @RateLimitTier('public-read')
  @ApiOperation({ summary: 'Admin retrieval of recent crash/issue reports' })
  @ApiResponse({
    status: 200,
    description: 'Crash reports retrieved successfully',
    type: [CrashReportDto],
  })
  async getAdminReports(): Promise<CrashReportDto[]> {
    const reports = await this.crashReportingService.getAllReports(50);
    
    return reports.map(report => ({
      id: report.id,
      userId: report.userId,
      error: report.error,
      context: report.context,
      logLines: report.logLines,
      timestamp: report.timestamp,
      createdAt: report.createdAt,
    }));
  }
}
