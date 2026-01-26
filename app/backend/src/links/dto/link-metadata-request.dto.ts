import { IsNumber, IsString, IsBoolean, IsOptional, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class LinkMetadataRequestDto {
  @ApiProperty({
    description: 'Payment amount in specified asset',
    example: 50.5,
    minimum: 0.0000001,
    maximum: 1000000,
  })
  @IsNumber()
  @Min(0.0000001)
  @Max(1000000)
  @Type(() => Number)
  amount: number;

  @ApiPropertyOptional({
    description: 'Optional memo text (max 28 characters)',
    example: 'Payment for service',
    maxLength: 28,
  })
  @IsOptional()
  @IsString()
  memo?: string;

  @ApiPropertyOptional({
    description: 'Memo type',
    example: 'text',
    enum: ['text', 'id', 'hash', 'return'],
  })
  @IsOptional()
  @IsString()
  memoType?: string;

  @ApiPropertyOptional({
    description: 'Asset code',
    example: 'XLM',
    enum: ['XLM', 'USDC', 'AQUA', 'yXLM'],
  })
  @IsOptional()
  @IsString()
  asset?: string;

  @ApiPropertyOptional({
    description: 'Privacy flag',
    example: false,
  })
  @IsOptional()
  @IsBoolean()
  @Type(() => Boolean)
  privacy?: boolean;

  @ApiPropertyOptional({
    description: 'Expiration in days',
    example: 30,
    minimum: 1,
    maximum: 365,
  })
  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  expirationDays?: number;
}
