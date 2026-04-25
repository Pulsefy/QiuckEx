import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { RefundableEntityType, RefundReasonCode } from '../refunds.types';

export class InitiateRefundDto {
  @ApiProperty({ enum: ['payment', 'escrow', 'link'] })
  entityType: RefundableEntityType;

  @ApiProperty()
  entityId: string;

  @ApiProperty()
  idempotencyKey: string;

  @ApiProperty({ enum: ['DUPLICATE', 'FRAUD', 'CUSTOMER_REQUEST', 'TECHNICAL_ERROR'] })
  reasonCode: RefundReasonCode;

  @ApiPropertyOptional()
  notes?: string;
}
