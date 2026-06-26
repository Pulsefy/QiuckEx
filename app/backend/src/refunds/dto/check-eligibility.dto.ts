import { ApiProperty } from '@nestjs/swagger';
import { IsIn, IsString } from 'class-validator';
import { RefundableEntityType } from '../refunds.types';

export class CheckEligibilityDto {
  @ApiProperty({ enum: ['payment', 'escrow', 'link'] })
  @IsIn(['payment', 'escrow', 'link'])
  entityType: RefundableEntityType;

  @ApiProperty()
  @IsString()
  entityId: string;
}
