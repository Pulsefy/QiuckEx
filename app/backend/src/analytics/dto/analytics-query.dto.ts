import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsEnum, IsISO8601, IsNotEmpty, IsOptional, IsString, Matches } from 'class-validator';

export enum AnalyticsInterval {
  DAILY = 'daily',
  WEEKLY = 'weekly',
  MONTHLY = 'monthly',
}

export enum ReportFormat {
  CSV = 'csv',
  PDF = 'pdf',
}

export enum ReportType {
  TAX = 'tax',
  ACCOUNTING = 'accounting',
}

export class AnalyticsQueryDto {
  @ApiProperty({
    description: 'Stellar public key for the user whose payment analytics should be returned',
    example: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
  })
  @IsNotEmpty()
  @IsString()
  @Matches(/^G[A-Z2-7]{55}$/, { message: 'Invalid Stellar public key format' })
  publicKey: string;

  @ApiPropertyOptional({
    description: 'Start date (inclusive) in ISO-8601 format',
    example: '2026-01-01T00:00:00.000Z',
  })
  @IsOptional()
  @IsISO8601()
  startDate?: string;

  @ApiPropertyOptional({
    description: 'End date (inclusive) in ISO-8601 format',
    example: '2026-04-29T23:59:59.999Z',
  })
  @IsOptional()
  @IsISO8601()
  endDate?: string;
}

export class TimeSeriesQueryDto extends AnalyticsQueryDto {
  @ApiPropertyOptional({
    description: 'Time bucket for chart rendering',
    enum: AnalyticsInterval,
    default: AnalyticsInterval.DAILY,
  })
  @IsOptional()
  @IsEnum(AnalyticsInterval)
  interval: AnalyticsInterval = AnalyticsInterval.DAILY;
}

export class ExportReportQueryDto extends AnalyticsQueryDto {
  @ApiPropertyOptional({
    description: 'Export format',
    enum: ReportFormat,
    default: ReportFormat.CSV,
  })
  @IsOptional()
  @IsEnum(ReportFormat)
  format: ReportFormat = ReportFormat.CSV;

  @ApiPropertyOptional({
    description: 'Report type preset',
    enum: ReportType,
    default: ReportType.ACCOUNTING,
  })
  @IsOptional()
  @IsEnum(ReportType)
  reportType: ReportType = ReportType.ACCOUNTING;

  @ApiPropertyOptional({
    description: 'Time bucket used in the exported trend section',
    enum: AnalyticsInterval,
    default: AnalyticsInterval.MONTHLY,
  })
  @IsOptional()
  @IsEnum(AnalyticsInterval)
  interval: AnalyticsInterval = AnalyticsInterval.MONTHLY;

  @ApiPropertyOptional({
    description: 'Maximum transaction rows to include in the export',
    example: 500,
    default: 500,
  })
  @IsOptional()
  @Type(() => Number)
  maxRows: number = 500;
}

