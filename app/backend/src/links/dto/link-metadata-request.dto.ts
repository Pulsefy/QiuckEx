import { IsNumber, IsString, IsBoolean, IsOptional, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';

export class LinkMetadataRequestDto {
  @IsNumber()
  @Min(0.0000001)
  @Max(1000000)
  @Type(() => Number)
  amount: number;

  @IsOptional()
  @IsString()
  memo?: string;

  @IsOptional()
  @IsString()
  memoType?: string;

  @IsOptional()
  @IsString()
  asset?: string;

  @IsOptional()
  @IsBoolean()
  @Type(() => Boolean)
  privacy?: boolean;

  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  expirationDays?: number;
}
