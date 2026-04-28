import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsOptional, IsDateString, IsArray, IsString } from 'class-validator';

export enum TimeGrouping {
  DAILY = 'daily',
  WEEKLY = 'weekly',
  MONTHLY = 'monthly',
}

export enum MetricType {
  VOLUME = 'volume',
  FEES = 'fees',
  SUCCESS_RATE = 'success_rate',
  ACTIVE_LINKS = 'active_links',
  PAID_LINKS = 'paid_links',
  AVERAGE_TRANSACTION = 'average_transaction',
}

/**
 * Base query parameters for metrics endpoints
 */
export class MetricsQueryDto {
  @ApiProperty({
    description: 'Start date (ISO 8601 format)',
    example: '2026-04-01T00:00:00Z',
  })
  @IsDateString()
  startDate: string;

  @ApiProperty({
    description: 'End date (ISO 8601 format)',
    example: '2026-04-28T23:59:59Z',
  })
  @IsDateString()
  endDate: string;

  @ApiProperty({
    description: 'Time grouping granularity',
    enum: TimeGrouping,
    example: TimeGrouping.DAILY,
    default: TimeGrouping.DAILY,
  })
  @IsEnum(TimeGrouping)
  @IsOptional()
  grouping?: TimeGrouping = TimeGrouping.DAILY;

  @ApiPropertyOptional({
    description: 'Filter by specific asset codes (comma-separated)',
    example: 'XLM,USDC',
  })
  @IsOptional()
  @IsString()
  assets?: string;

  @ApiPropertyOptional({
    description: 'Include zero-value data points',
    example: false,
    default: false,
  })
  @IsOptional()
  includeZeros?: boolean = false;
}

/**
 * Query for daily/weekly/monthly aggregated stats
 */
export class StatsQueryDto extends MetricsQueryDto {
  @ApiPropertyOptional({
    description: 'Include breakdown by asset',
    example: true,
    default: false,
  })
  @IsOptional()
  breakdownByAsset?: boolean = false;

  @ApiPropertyOptional({
    description: 'Include comparison with previous period',
    example: true,
    default: false,
  })
  @IsOptional()
  includeComparison?: boolean = false;
}
