import { Controller, Get, Query, Req, Res, UseGuards } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request, Response } from 'express';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RateLimitTier } from '../auth/decorators/rate-limit-group.decorator';
import { AnalyticsService } from './analytics.service';
import {
  AnalyticsQueryDto,
  ExportReportQueryDto,
  TimeSeriesQueryDto,
  ReportFormat,
} from './dto/analytics-query.dto';
import { DashboardSummaryQueryDto } from './dto/dashboard-summary.dto';
import { EmitAnalyticsEventDto } from './dto/analytics-event.dto';
import { SchemaRegistryService } from './schema-registry.service';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Post, Body } from '@nestjs/common';

@ApiTags('analytics')
@UseGuards(ApiKeyGuard)
@Controller('analytics')
export class AnalyticsController {
  constructor(
    private readonly analyticsService: AnalyticsService,
    private readonly schemaRegistry: SchemaRegistryService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  @Get('report')
  @RateLimitTier('public-read')
  @ApiOperation({
    summary: 'Fetch dashboard analytics report (summary, asset distribution, and time-series)',
  })
  @ApiResponse({ status: 200, description: 'Analytics report generated' })
  async getReport(@Req() req: Request, @Query() query: TimeSeriesQueryDto) {
    return this.analyticsService.getAnalyticsReport(
      query.publicKey,
      query.startDate,
      query.endDate,
      query.interval,
      req.organizationContext?.organizationId,
    );
  }

  @Get('time-series')
  @RateLimitTier('public-read')
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
  @RateLimitTier('public-read')
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
  @RateLimitTier('export')
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

  @Get('dashboard-summary')
  @RateLimitTier('public-read')
  @ApiOperation({
    summary: 'Fetch compact dashboard summary metrics for header cards',
  })
  @ApiResponse({ status: 200, description: 'Dashboard summary generated' })
  async getDashboardSummary(@Req() req: Request, @Query() query: DashboardSummaryQueryDto) {
    return this.analyticsService.getDashboardSummary(
      query.publicKey,
      query.timeRange,
      query.startDate,
      query.endDate,
      req.organizationContext?.organizationId,
    );
  }

  @Get('schemas')
  @RateLimitTier('public-read')
  @ApiOperation({
    summary: 'Export analytics event schemas for consumers and dashboards',
  })
  @ApiResponse({ status: 200, description: 'Event schema registry exported' })
  getSchemas() {
    return this.schemaRegistry.exportRegistry();
  }

  @Post('events')
  @RateLimitTier('public-write')
  @ApiOperation({ summary: 'Emit and validate an analytics event' })
  @ApiResponse({ status: 201, description: 'Event validated and recorded' })
  recordEvent(@Body() dto: EmitAnalyticsEventDto) {
    const validatedData = this.schemaRegistry.validateEvent(
      dto.eventName,
      dto.version,
      dto.payload,
    );
    
    this.eventEmitter.emit(`analytics.${dto.eventName}`, {
      version: dto.version,
      data: validatedData,
      timestamp: new Date().toISOString(),
    });
    
    return { success: true };
  }
}
