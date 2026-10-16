import {
  BadRequestException,
  Body,
  Controller,
  Get,
  NotFoundException,
  Optional,
  Param,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
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
import { AnalyticsEventRegistryService } from './events/analytics-event-registry.service';

@ApiTags('analytics')
@UseGuards(ApiKeyGuard)
@Controller('analytics')
export class AnalyticsController {
  constructor(
    private readonly analyticsService: AnalyticsService,
    @Optional()
    private readonly eventRegistry: AnalyticsEventRegistryService = new AnalyticsEventRegistryService(),
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
    summary: 'Export the central analytics event schema registry for dashboards and consumers',
  })
  @ApiResponse({ status: 200, description: 'Analytics event schema registry exported' })
  getSchemas() {
    return this.eventRegistry.exportRegistry();
  }

  @Get('schemas/:eventName')
  @RateLimitTier('public-read')
  @ApiOperation({
    summary: 'Export a single analytics event schema by event name',
  })
  @ApiResponse({ status: 200, description: 'Analytics event schema returned' })
  @ApiResponse({ status: 404, description: 'Event schema not found' })
  getEventSchema(@Param('eventName') eventName: string) {
    const schema = this.eventRegistry.exportEventSchema(eventName);
    if (!schema) {
      throw new NotFoundException({
        code: 'ANALYTICS_SCHEMA_NOT_FOUND',
        message: `Analytics event schema "${eventName}" was not found in the registry`,
      });
    }
    return schema;
  }

  @Post('events')
  @RateLimitTier('authenticated')
  @ApiOperation({
    summary: 'Validate and record an analytics event against its registered schema',
  })
  @ApiResponse({ status: 201, description: 'Analytics event validated and recorded' })
  @ApiResponse({ status: 400, description: 'Analytics event failed schema validation' })
  emitEvent(@Body() body: EmitAnalyticsEventDto) {
    const result = this.eventRegistry.emit(body);
    if (!result.accepted) {
      throw new BadRequestException({
        code: 'ANALYTICS_EVENT_SCHEMA_INVALID',
        message: `Event "${body.eventName}" failed schema validation`,
        eventName: result.validation.eventName,
        schemaVersion: result.validation.schemaVersion,
        issues: result.validation.issues,
      });
    }
    return result;
  }

  @Get('events/stats')
  @RateLimitTier('public-read')
  @ApiOperation({
    summary: 'Fetch analytics event schema validation and rejection counters',
  })
  @ApiResponse({ status: 200, description: 'Analytics event validation stats returned' })
  getEventValidationStats() {
    return this.eventRegistry.getValidationStats();
  }
}
