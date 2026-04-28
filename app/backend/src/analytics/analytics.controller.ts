import {
  Controller,
  Get,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
  Req,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiHeader,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { Request } from 'express';

import { AnalyticsService } from './analytics.service';
import {
  StatsQueryDto,
} from './dto/metrics-query.dto';
import {
  AggregatedStatsResponseDto,
  ComparisonResponseDto,
} from './dto/metrics-response.dto';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';

/**
 * Analytics API Controller
 *
 * Provides aggregated usage and financial metrics for authenticated users.
 * All endpoints require organization context (inferred from API key or auth token).
 */
@ApiTags('analytics')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Optional API key for developer portal access',
  required: false,
})
@ApiBearerAuth('bearer')
@UseGuards(ApiKeyGuard)
@Controller('analytics')
export class AnalyticsController {
  constructor(private readonly analyticsService: AnalyticsService) {}

  /**
   * Get aggregated statistics for a date range
   *
   * Returns time-series metrics (volume, fees, success rate, active links) grouped by
   * specified granularity (daily/weekly/monthly). Supports filtering by asset and
   * optional comparison with previous period.
   *
   * Response times are optimized with caching; typical queries complete within 500ms.
   * Large date ranges (>2 years) may require longer processing.
   */
  @Get('stats')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get aggregated statistics for a date range',
    description:
      'Fetches time-series metrics (volume, fees, success rates, active links) for a specified date range. ' +
      'Results are grouped by daily/weekly/monthly granularity. Supports asset filtering and optional comparison data. ' +
      'Uses caching to optimize performance; typical response time is <500ms.',
  })
  @ApiResponse({
    status: 200,
    description: 'Aggregated statistics with time-series data',
    type: AggregatedStatsResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid query parameters or date range',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - invalid or missing credentials',
  })
  @ApiResponse({
    status: 429,
    description: 'Rate limit exceeded',
  })
  async getStats(
    @Query() query: StatsQueryDto,
    @Req() request: Request,
  ): Promise<AggregatedStatsResponseDto> {
    // Get account ID from API key context
    // In production: extract from authenticated user/organization
    const accountId = this.extractAccountId(request);

    return this.analyticsService.getAggregatedStats(accountId, query);
  }

  /**
   * Compare current period with previous period
   *
   * Returns side-by-side comparison of metrics with percentage changes.
   * Automatically calculates the previous period based on the specified date range.
   */
  @Get('stats/comparison')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Compare current period with previous period',
    description:
      'Compare metrics for the requested date range with the equivalent previous period. ' +
      'Returns percentage changes for all key metrics.',
  })
  @ApiResponse({
    status: 200,
    description: 'Current and previous period metrics with comparison',
    type: ComparisonResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid query parameters or date range',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - invalid or missing credentials',
  })
  async compareWithPreviousPeriod(
    @Query() query: StatsQueryDto,
    @Req() request: Request,
  ): Promise<ComparisonResponseDto> {
    const accountId = this.extractAccountId(request);

    return this.analyticsService.compareWithPreviousPeriod(accountId, query);
  }

  /**
   * Extract account ID from request context
   * In a real implementation, this would extract from authenticated user/organization
   */
  private extractAccountId(request: Request): string {
    // This could be populated by the API key guard or JWT auth middleware
    const apiKey = (request as any).apiKey;
    if (apiKey) {
      // In production: use apiKey.organizationId or similar
      return apiKey.id || 'default-org';
    }

    // Default fallback for testing
    const query = request.query as Record<string, string>;
    return query.accountId || 'default-org';
  }
}
