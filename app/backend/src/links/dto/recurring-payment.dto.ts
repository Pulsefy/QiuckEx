import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsNumber, IsOptional, IsString, Min, Max, IsBoolean, IsDateString } from 'class-validator';

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export enum FrequencyType {
  DAILY = 'daily',
  WEEKLY = 'weekly',
  MONTHLY = 'monthly',
  YEARLY = 'yearly',
}

export enum RecurringStatus {
  ACTIVE = 'active',
  PAUSED = 'paused',
  COMPLETED = 'completed',
  CANCELLED = 'cancelled',
}

export enum ExecutionStatus {
  PENDING = 'pending',
  SUCCESS = 'success',
  FAILED = 'failed',
  SKIPPED = 'skipped',
}

// ---------------------------------------------------------------------------
// Request DTOs
// ---------------------------------------------------------------------------

/**
 * DTO for creating a new recurring payment link
 */
export class CreateRecurringPaymentLinkDto {
  @ApiProperty({
    description: 'Payment amount',
    example: 100,
    minimum: 1,
  })
  @IsNumber()
  @Min(1)
  amount!: number;

  @ApiProperty({
    description: 'Asset code (XLM, USDC, etc.)',
    example: 'XLM',
  })
  @IsString()
  asset!: string;

  @ApiPropertyOptional({
    description: 'Asset issuer address (for non-native assets)',
    example: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2K34P4D5NXJ6Z4GJ5B7G',
  })
  @IsString()
  @IsOptional()
  assetIssuer?: string;

  @ApiProperty({
    description: 'Username route (quickex.to/username)',
    example: 'john_doe',
    required: false,
  })
  @IsString()
  @IsOptional()
  username?: string;

  @ApiPropertyOptional({
    description: 'Direct Stellar public key destination',
    example: 'G...56 characters',
  })
  @IsString()
  @IsOptional()
  destination?: string;

  @ApiProperty({
    description: 'Payment frequency',
    enum: FrequencyType,
    example: FrequencyType.MONTHLY,
  })
  @IsEnum(FrequencyType)
  frequency!: FrequencyType;

  @ApiPropertyOptional({
    description: 'Start date for the recurring payments (ISO 8601)',
    example: '2025-03-26T00:00:00Z',
  })
  @IsDateString()
  @IsOptional()
  startDate?: string;

  @ApiPropertyOptional({
    description: 'End date for the recurring payments (ISO 8601)',
    example: '2026-03-26T00:00:00Z',
  })
  @IsDateString()
  @IsOptional()
  endDate?: string;

  @ApiPropertyOptional({
    description: 'Total number of payments (null for indefinite)',
    example: 12,
    minimum: 1,
  })
  @IsNumber()
  @Min(1)
  @IsOptional()
  totalPeriods?: number;

  @ApiPropertyOptional({
    description: 'Payment memo/note',
    example: 'Monthly subscription',
  })
  @IsString()
  @IsOptional()
  memo?: string;

  @ApiPropertyOptional({
    description: 'Memo type',
    enum: ['text', 'id', 'hash', 'return'],
    default: 'text',
  })
  @IsString()
  @IsOptional()
  memoType?: string;

  @ApiPropertyOptional({
    description: 'Reference ID for tracking',
    example: 'SUB-2025-001',
  })
  @IsString()
  @IsOptional()
  referenceId?: string;

  @ApiPropertyOptional({
    description: 'Enable X-Ray privacy (hide amounts/senders)',
    default: false,
  })
  @IsBoolean()
  @IsOptional()
  privacyEnabled?: boolean;
}

/**
 * DTO for updating an existing recurring payment link
 */
export class UpdateRecurringPaymentLinkDto {
  @ApiPropertyOptional({
    description: 'Payment amount',
    example: 150,
    minimum: 1,
  })
  @IsNumber()
  @Min(1)
  @IsOptional()
  amount?: number;

  @ApiPropertyOptional({
    description: 'Payment frequency',
    enum: FrequencyType,
  })
  @IsEnum(FrequencyType)
  @IsOptional()
  frequency?: FrequencyType;

  @ApiPropertyOptional({
    description: 'End date for the recurring payments (ISO 8601)',
  })
  @IsDateString()
  @IsOptional()
  endDate?: string;

  @ApiPropertyOptional({
    description: 'Total number of payments',
    minimum: 1,
  })
  @IsNumber()
  @Min(1)
  @IsOptional()
  totalPeriods?: number;

  @ApiPropertyOptional({
    description: 'Payment memo/note',
  })
  @IsString()
  @IsOptional()
  memo?: string;

  @ApiPropertyOptional({
    description: 'Reference ID for tracking',
  })
  @IsString()
  @IsOptional()
  referenceId?: string;
}

// ---------------------------------------------------------------------------
// Response DTOs
// ---------------------------------------------------------------------------

/**
 * DTO for recurring payment execution details
 */
export class RecurringPaymentExecutionDto {
  @ApiProperty({ description: 'Execution ID' })
  id!: string;

  @ApiProperty({ description: 'Period number' })
  periodNumber!: number;

  @ApiProperty({ description: 'Scheduled execution time' })
  scheduledAt!: Date;

  @ApiPropertyOptional({ description: 'Actual execution time' })
  executedAt?: Date;

  @ApiProperty({ description: 'Payment amount' })
  amount!: number;

  @ApiProperty({ description: 'Asset code' })
  asset!: string;

  @ApiProperty({ description: 'Execution status', enum: ExecutionStatus })
  status!: ExecutionStatus;

  @ApiPropertyOptional({ description: 'Stellar transaction hash' })
  transactionHash?: string;

  @ApiPropertyOptional({ description: 'Failure reason' })
  failureReason?: string;

  @ApiProperty({ description: 'Retry count' })
  retryCount!: number;

  @ApiProperty({ description: 'Notification sent flag' })
  notificationSent!: boolean;

  @ApiProperty({ description: 'Created timestamp' })
  createdAt!: Date;
}

/**
 * DTO for recurring payment link response
 */
export class RecurringPaymentLinkResponseDto {
  @ApiProperty({ description: 'Recurring link ID' })
  id!: string;

  @ApiPropertyOptional({ description: 'Username route' })
  username?: string;

  @ApiPropertyOptional({ description: 'Destination public key' })
  destination?: string;

  @ApiProperty({ description: 'Payment amount' })
  amount!: number;

  @ApiProperty({ description: 'Asset code' })
  asset!: string;

  @ApiPropertyOptional({ description: 'Asset issuer' })
  assetIssuer?: string;

  @ApiProperty({ description: 'Payment frequency', enum: FrequencyType })
  frequency!: FrequencyType;

  @ApiProperty({ description: 'Start date' })
  startDate!: Date;

  @ApiPropertyOptional({ description: 'End date' })
  endDate?: Date;

  @ApiPropertyOptional({ description: 'Total periods' })
  totalPeriods?: number;

  @ApiProperty({ description: 'Number of executed payments' })
  executedCount!: number;

  @ApiProperty({ description: 'Next execution date' })
  nextExecutionDate!: Date;

  @ApiProperty({ description: 'Current status', enum: RecurringStatus })
  status!: RecurringStatus;

  @ApiPropertyOptional({ description: 'Payment memo' })
  memo?: string;

  @ApiPropertyOptional({ description: 'Memo type' })
  memoType?: string;

  @ApiPropertyOptional({ description: 'Reference ID' })
  referenceId?: string;

  @ApiProperty({ description: 'Privacy enabled flag' })
  privacyEnabled!: boolean;

  @ApiProperty({ description: 'Creation timestamp' })
  createdAt!: Date;

  @ApiProperty({ description: 'Last update timestamp' })
  updatedAt!: Date;

  @ApiPropertyOptional({
    description: 'Execution history',
    type: [RecurringPaymentExecutionDto],
  })
  executions?: RecurringPaymentExecutionDto[];
}

/**
 * DTO for listing recurring payment links
 */
export class ListRecurringPaymentsResponseDto {
  @ApiProperty({ description: 'Success flag' })
  success!: boolean;

  @ApiProperty({ description: 'Total count' })
  total!: number;

  @ApiProperty({
    description: 'Recurring payment links',
    type: [RecurringPaymentLinkResponseDto],
  })
  data!: RecurringPaymentLinkResponseDto[];
}

// ---------------------------------------------------------------------------
// Query Parameter DTOs
// ---------------------------------------------------------------------------

/**
 * DTO for querying recurring payment links
 */
export class QueryRecurringPaymentsDto {
  @ApiPropertyOptional({
    description: 'Filter by status',
    enum: RecurringStatus,
  })
  @IsEnum(RecurringStatus)
  @IsOptional()
  status?: RecurringStatus;

  @ApiPropertyOptional({
    description: 'Filter by username',
  })
  @IsString()
  @IsOptional()
  username?: string;

  @ApiPropertyOptional({
    description: 'Filter by destination',
  })
  @IsString()
  @IsOptional()
  destination?: string;

  @ApiPropertyOptional({
    description: 'Page number',
    example: 1,
    minimum: 1,
  })
  @IsNumber()
  @Min(1)
  @IsOptional()
  page?: number;

  @ApiPropertyOptional({
    description: 'Items per page',
    example: 20,
    minimum: 1,
    maximum: 100,
  })
  @IsNumber()
  @Min(1)
  @Max(100)
  @IsOptional()
  limit?: number;
}
