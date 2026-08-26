import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsISO8601, IsNotEmpty, IsOptional, IsString, Matches } from 'class-validator';

export enum TimeRange {
  TODAY = 'today',
  WEEK = 'week',
  MONTH = 'month',
  CUSTOM = 'custom',
}

export class DashboardSummaryQueryDto {
  @ApiProperty({
    description: 'Stellar public key for the user whose dashboard summary should be returned',
    example: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
  })
  @IsNotEmpty()
  @IsString()
  @Matches(/^G[A-Z2-7]{55}$/, { message: 'Invalid Stellar public key format' })
  publicKey: string;

  @ApiPropertyOptional({
    description: 'Time range preset',
    enum: TimeRange,
    default: TimeRange.WEEK,
  })
  @IsOptional()
  @IsEnum(TimeRange)
  timeRange: TimeRange = TimeRange.WEEK;

  @ApiPropertyOptional({
    description: 'Start date (inclusive) in ISO-8601 format (required when timeRange is custom)',
    example: '2026-01-01T00:00:00.000Z',
  })
  @IsOptional()
  @IsISO8601()
  startDate?: string;

  @ApiPropertyOptional({
    description: 'End date (inclusive) in ISO-8601 format (required when timeRange is custom)',
    example: '2026-04-29T23:59:59.999Z',
  })
  @IsOptional()
  @IsISO8601()
  endDate?: string;
}
