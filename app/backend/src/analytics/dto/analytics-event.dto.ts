import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsInt,
  IsISO8601,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  Min,
} from 'class-validator';

export class EmitAnalyticsEventDto {
  @ApiProperty({
    description: 'Registered analytics event name (e.g. "payment.completed")',
    example: 'payment.completed',
  })
  @IsString()
  @IsNotEmpty()
  eventName!: string;

  @ApiProperty({
    description: 'Event payload validated against the registered versioned schema',
    example: {
      paymentId: 'pay_123',
      txHash: 'abc123def456',
      asset: 'USDC',
      amount: 25,
      amountUsd: 25,
    },
  })
  @IsObject()
  payload!: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Expected schema version for the event',
    example: 1,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  schemaVersion?: number;

  @ApiPropertyOptional({
    description: 'ISO-8601 timestamp when the event occurred',
    example: '2026-04-16T12:00:00.000Z',
  })
  @IsOptional()
  @IsISO8601()
  occurredAt?: string;

  @ApiPropertyOptional({
    description: 'Optional producer metadata envelope',
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Whether undeclared fields are allowed in the payload',
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  allowExtraFields?: boolean;
}
