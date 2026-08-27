import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsNumber, IsOptional, IsString, MaxLength, Min } from 'class-validator';
import { Type } from 'class-transformer';

import { CursorPaginationQueryDto } from '../../dto/pagination/pagination.dto';
import { MARKETPLACE_SORT_OPTIONS, MarketplaceSortOption } from '../marketplace-listing-query';

/**
 * Query params for GET /marketplace.
 * Extends the standard cursor pagination DTO with marketplace-specific
 * sort and filter options.
 */
export class GetMarketplaceListingsDto extends CursorPaginationQueryDto {
  @ApiPropertyOptional({
    description: 'Sort order for listings',
    enum: MARKETPLACE_SORT_OPTIONS,
    default: 'newest',
  })
  @IsOptional()
  @IsIn(MARKETPLACE_SORT_OPTIONS)
  sort?: MarketplaceSortOption = 'newest';

  @ApiPropertyOptional({
    description: 'Minimum asking price, inclusive',
    example: 100,
  })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  min_price?: number;

  @ApiPropertyOptional({
    description: 'Maximum asking price, inclusive',
    example: 5000,
  })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  max_price?: number;

  @ApiPropertyOptional({
    description: 'Filter listings by username substring (case-insensitive)',
    example: 'sat',
  })
  @IsOptional()
  @IsString()
  @MaxLength(64)
  username?: string;
}
