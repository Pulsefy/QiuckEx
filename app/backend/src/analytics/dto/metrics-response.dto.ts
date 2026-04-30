import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

/**
 * Asset-specific metric breakdown
 */
export class AssetMetricDto {
  @ApiProperty({
    description: 'Asset code (e.g., XLM, USDC)',
    example: 'XLM',
  })
  asset: string;

  @ApiProperty({
    description: 'Total volume in asset units',
    example: '1000.50',
  })
  volume: string;

  @ApiProperty({
    description: 'Total fees in XLM',
    example: '0.0001',
  })
  fees: string;

  @ApiProperty({
    description: 'Success rate as percentage (0-100)',
    example: 95.5,
  })
  successRate: number;

  @ApiProperty({
    description: 'Number of unique payment links used',
    example: 42,
  })
  activeLinks: number;

  @ApiProperty({
    description: 'Number of links that received at least one payment',
    example: 38,
  })
  paidLinks: number;

  @ApiProperty({
    description: 'Average transaction amount',
    example: '50.25',
  })
  averageTransaction: string;

  @ApiProperty({
    description: 'Total number of transactions',
    example: 156,
  })
  transactionCount: number;
}

/**
 * Period-specific aggregated metrics
 */
export class PeriodMetricDto {
  @ApiProperty({
    description: 'Period start date (ISO 8601)',
    example: '2026-04-01T00:00:00Z',
  })
  period: string;

  @ApiProperty({
    description: 'Total volume across all assets',
    example: '5000.75',
  })
  totalVolume: string;

  @ApiProperty({
    description: 'Total fees in XLM',
    example: '0.0005',
  })
  totalFees: string;

  @ApiProperty({
    description: 'Overall success rate as percentage (0-100)',
    example: 92.3,
  })
  successRate: number;

  @ApiProperty({
    description: 'Total unique payment links used',
    example: 120,
  })
  totalActiveLinks: number;

  @ApiProperty({
    description: 'Total links that received at least one payment',
    example: 108,
  })
  totalPaidLinks: number;

  @ApiProperty({
    description: 'Average transaction amount across all assets',
    example: '42.31',
  })
  averageTransaction: string;

  @ApiProperty({
    description: 'Total number of transactions in period',
    example: 118,
  })
  transactionCount: number;

  @ApiPropertyOptional({
    description: 'Per-asset breakdown if requested',
    type: [AssetMetricDto],
  })
  assetBreakdown?: AssetMetricDto[];

  @ApiPropertyOptional({
    description: 'Comparison with previous period if requested',
  })
  comparison?: PeriodComparisonDto;
}

/**
 * Comparison between current and previous periods
 */
export class PeriodComparisonDto {
  @ApiProperty({
    description: 'Previous period start date (ISO 8601)',
    example: '2026-03-25T00:00:00Z',
  })
  previousPeriod: string;

  @ApiProperty({
    description: 'Volume change percentage',
    example: 15.2,
  })
  volumeChangePercent: number;

  @ApiProperty({
    description: 'Success rate change in percentage points',
    example: 2.5,
  })
  successRateChangePercent: number;

  @ApiProperty({
    description: 'Active links change percentage',
    example: 8.3,
  })
  activeLinksChangePercent: number;

  @ApiProperty({
    description: 'Paid links change percentage',
    example: 12.1,
  })
  paidLinksChangePercent: number;

  @ApiProperty({
    description: 'Average transaction change percentage',
    example: -5.5,
  })
  averageTransactionChangePercent: number;

  @ApiProperty({
    description: 'Transaction count change (absolute)',
    example: 35,
  })
  transactionCountChange: number;
}

/**
 * Response DTO for aggregated stats endpoint
 */
export class AggregatedStatsResponseDto {
  @ApiProperty({
    description: 'Summary statistics for the requested period',
  })
  summary: PeriodMetricDto;

  @ApiProperty({
    description: 'Time-series data points',
    type: [PeriodMetricDto],
  })
  timeSeries: PeriodMetricDto[];

  @ApiPropertyOptional({
    description: 'Metadata about the query',
  })
  metadata?: {
    requestedStartDate: string;
    requestedEndDate: string;
    granularity: string;
    assetFilter?: string[];
    generatedAt: string;
    executionTimeMs: number;
  };
}

/**
 * Response DTO for comparison endpoint
 */
export class ComparisonResponseDto {
  @ApiProperty({
    description: 'Current period metrics',
  })
  current: PeriodMetricDto;

  @ApiProperty({
    description: 'Previous period metrics for comparison',
  })
  previous: PeriodMetricDto;

  @ApiProperty({
    description: 'Comparison analysis',
  })
  comparison: PeriodComparisonDto;

  @ApiPropertyOptional({
    description: 'Metadata about the query',
  })
  metadata?: {
    generatedAt: string;
    executionTimeMs: number;
  };
}
