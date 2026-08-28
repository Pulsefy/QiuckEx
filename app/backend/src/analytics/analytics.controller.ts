import { Controller, Get, Query, Req, Res, Sse, UseGuards } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request, Response } from 'express';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { AnalyticsService } from './analytics.service';
import { AnalyticsEventsService } from './analytics-events.service';
import {
  AnalyticsQueryDto,
  ExportReportQueryDto,
  TimeSeriesQueryDto,
  ReportFormat,
} from './dto/analytics-query.dto';

@ApiTags('analytics')
@UseGuards(ApiKeyGuard)
@Controller('analytics')
export class AnalyticsController {
  constructor(
    private readonly analyticsService: AnalyticsService,
    private readonly analyticsEventsService: AnalyticsEventsService,
  ) {}

  @Sse('events')
  @ApiOperation({ summary: 'Stream analytics updates for a public key' })
  events(@Query('publicKey') publicKey: string) {
    return this.analyticsEventsService.stream(publicKey);
  }

  @Get('report')
  @ApiOperation({
    summary: 'Fetch dashboard analytics report (summary, asset distribution, and time-series)',
  })
  @ApiResponse({ status: 200, description: 'Analytics report generated' })
  async getReport(
    @Req() req: Request,
    @Res() res: Response,
    @Query() query: TimeSeriesQueryDto,
  ) {
    const { report, cacheStatus } =
      await this.analyticsService.getAnalyticsReportWithStatus(
        query.publicKey,
        query.startDate,
        query.endDate,
        query.interval,
        req.organizationContext?.organizationId,
      );

    if (cacheStatus === 'stale') {
      res.set('X-Cache-Status', 'stale');
      res.set('X-QuickEx-Stale-Data', 'true');
    } else {
      res.set('X-Cache-Status', 'fresh');
    }

    return res.status(200).json(report);
  }

  @Get('time-series')
  @ApiOperation({
    summary: 'Fetch only time-series analytics for chart rendering (daily/weekly/monthly)',
  })
  @ApiResponse({ status: 200, description: 'Time-series analytics generated' })
  async getTimeSeries(@Req() req: Request, @Query() query: TimeSeriesQueryDto) {
    const report = await this.analyticsService.getAnalyticsReport(
      query.publicKey,
      query.startDate,
      query.endDate,
      query.interval,
      req.organizationContext?.organizationId,
    );
    return {
      interval: query.interval,
      window: report.window,
      series: report.timeSeries,
    };
  }

  @Get('assets')
  @ApiOperation({
    summary: 'Fetch asset distribution for payment history',
  })
  @ApiResponse({ status: 200, description: 'Asset distribution generated' })
  async getAssetDistribution(@Req() req: Request, @Query() query: AnalyticsQueryDto) {
    const report = await this.analyticsService.getAnalyticsReport(
      query.publicKey,
      query.startDate,
      query.endDate,
      undefined,
      req.organizationContext?.organizationId,
    );
    return {
      window: report.window,
      distribution: report.assetDistribution,
    };
  }

  @Get('export')
  @ApiOperation({
    summary: 'Export analytics report in CSV or PDF for tax/accounting',
  })
  @ApiResponse({ status: 200, description: 'Report export generated' })
  async exportReport(
    @Query() query: ExportReportQueryDto,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const { report, payments } = await this.analyticsService.exportReport(
      query.publicKey,
      query.startDate,
      query.endDate,
      query.reportType,
      query.interval,
      query.maxRows,
      req.organizationContext?.organizationId,
    );

    if (query.format === ReportFormat.PDF) {
      const pdf = this.analyticsService.buildPdfReport(
        report,
        payments,
        query.reportType,
      );
      const filename = `quickex-${query.reportType}-report.pdf`;
      res.header('Content-Type', 'application/pdf');
      res.attachment(filename);
      return res.send(pdf);
    }

    const csv = this.analyticsService.buildCsvReport(
      report,
      payments,
      query.reportType,
    );
    const filename = `quickex-${query.reportType}-report.csv`;
    res.header('Content-Type', 'text/csv');
    res.attachment(filename);
    return res.send(csv);
  }
}
