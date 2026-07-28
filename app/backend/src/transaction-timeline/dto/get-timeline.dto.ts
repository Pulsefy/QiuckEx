import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsOptional, IsIn, IsInt, Min, Max } from 'class-validator';
import { Transform } from 'class-transformer';
import type { TimelineEventKind } from '../transaction-timeline.types';

export class GetTimelineQueryDto {
  @ApiProperty({
    description: 'Stellar transaction hash to build the timeline for.',
    example: 'a1b2c3d4...',
  })
  @IsString()
  @IsNotEmpty()
  txHash: string;

  /**
   * Optional address to scope payment lookups (sender or receiver).
   * If omitted, all parties for the tx are included.
   */
  @ApiPropertyOptional({
    description: 'Stellar public key to scope webhook/refund lookups.',
  })
  @IsOptional()
  @IsString()
  address?: string;

  /** Filter to a specific event kind. */
  @ApiPropertyOptional({
    enum: ['payment', 'refund', 'webhook_delivery', 'contract_event'],
    description: 'Limit results to a single event kind.',
  })
  @IsOptional()
  @IsIn(['payment', 'refund', 'webhook_delivery', 'contract_event'])
  kind?: TimelineEventKind;

  @ApiPropertyOptional({
    description: 'Maximum number of timeline items to return (1–200).',
    default: 50,
  })
  @IsOptional()
  @Transform(({ value }) => parseInt(value as string, 10))
  @IsInt()
  @Min(1)
  @Max(200)
  limit?: number = 50;
}
