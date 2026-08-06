import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsDateString, IsOptional, IsString, IsArray, IsNumber, IsObject } from 'class-validator';

export class SeedResetConfigDto {
  @ApiProperty({ example: true })
  @IsBoolean()
  enabled: boolean;

  @ApiProperty({ example: '0 0 * * *' })
  @IsString()
  interval: string;

  @ApiPropertyOptional({ example: ['prod', 'staging'] })
  @IsArray()
  @IsOptional()
  exclusions?: string[];

  @ApiPropertyOptional({ example: 3 })
  @IsNumber()
  @IsOptional()
  maxRetries?: number;

  @ApiPropertyOptional({ example: true })
  @IsBoolean()
  @IsOptional()
  retryOnFailure?: boolean;
}

export class SeedResetOptionsDto {
  @ApiPropertyOptional({ example: false })
  @IsBoolean()
  @IsOptional()
  force?: boolean;

  @ApiPropertyOptional({ example: ['usernames'] })
  @IsArray()
  @IsOptional()
  excludeTables?: string[];

  @ApiPropertyOptional({ example: 'manual-trigger' })
  @IsString()
  @IsOptional()
  trigger?: string;

  @ApiPropertyOptional({ example: { preserve: ['demo_user_1'] } })
  @IsObject()
  @IsOptional()
  preserveOptions?: Record<string, unknown>;
}

export class SeedResetReportDto {
  @ApiProperty({ example: '2026-08-05T12:00:00.000Z' })
  @IsDateString()
  timestamp: string;

  @ApiProperty({ example: true })
  @IsBoolean()
  success: boolean;

  @ApiProperty({ example: 4 })
  @IsNumber()
  seededLinks: number;

  @ApiProperty({ example: 4 })
  @IsNumber()
  seededTransactions: number;

  @ApiProperty({ example: 0 })
  @IsNumber()
  skippedLinks: number;

  @ApiProperty({ example: 0 })
  @IsNumber()
  skippedTransactions: number;

  @ApiPropertyOptional({ example: ['prod-exclusion'] })
  @IsArray()
  @IsOptional()
  exclusionsApplied?: string[];

  @ApiPropertyOptional({ type: [String] })
  @IsArray()
  @IsOptional()
  errors?: string[];

  @ApiPropertyOptional({ example: 5 })
  @IsNumber()
  @IsOptional()
  retryCount?: number;

  @ApiPropertyOptional({ example: '2026-08-05T11:59:00.000Z' })
  @IsDateString()
  @IsOptional()
  nextScheduled?: string;
}

export class SeedResetStatusDto {
  @ApiProperty({ example: true })
  enabled: boolean;

  @ApiProperty({ example: '0 0 * * *' })
  interval: string;

  @ApiProperty({ example: '2026-08-05T12:00:00.000Z' })
  @IsOptional()
  lastResetTime?: string;

  @ApiProperty({ example: 10 })
  totalResets: number;

  @ApiProperty({ example: 9 })
  successfulResets: number;

  @ApiProperty({ example: 1 })
  failedResets: number;

  @ApiPropertyOptional({ type: [String] })
  @IsOptional()
  exclusions?: string[];
}