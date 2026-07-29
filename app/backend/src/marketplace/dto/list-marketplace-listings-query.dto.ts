import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsInt, Min, Max, IsEnum, IsNumber } from 'class-validator';
import { Type } from 'class-transformer';
import { PAGINATION_DEFAULTS } from '../../common/pagination/cursor.util';

export enum MarketplaceSortField {
  NEWEST = 'newest',
  OLDEST = 'oldest',
  PRICE_ASC = 'price_asc',
  PRICE_DESC = 'price_desc',
  ENDING_SOON = 'ending_soon',
}

export enum MarketplaceListingStatus {
  ACTIVE = 'active',
  SOLD = 'sold',
  CANCELLED = 'cancelled',
  ALL = 'all',
}

export class ListMarketplaceListingsQueryDto {
  @ApiPropertyOptional({
    description: 'Page number (1-based). When provided, uses offset-based pagination.',
    minimum: 1,
    default: 1,
    example: 1,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @ApiPropertyOptional({
    description: 'Maximum number of items per page (1-100)',
    minimum: PAGINATION_DEFAULTS.LIMIT_MIN,
    maximum: PAGINATION_DEFAULTS.LIMIT_MAX,
    default: PAGINATION_DEFAULTS.LIMIT_DEFAULT,
    example: 20,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(PAGINATION_DEFAULTS.LIMIT_MIN)
  @Max(PAGINATION_DEFAULTS.LIMIT_MAX)
  limit?: number = PAGINATION_DEFAULTS.LIMIT_DEFAULT;

  @ApiPropertyOptional({
    description: 'Opaque cursor for cursor-based pagination (alternative to page)',
    example: 'eyJwayI6IjIwMjYtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImlkIjoiMTIzNDU2NzgtYWJjZC0xMjM0LTEyMzQtMTIzNDU2Nzg5MGFiIn0',
  })
  @IsOptional()
  @IsString()
  cursor?: string;

  @ApiPropertyOptional({
    description: 'Minimum asking price filter',
    example: 10,
  })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  minPrice?: number;

  @ApiPropertyOptional({
    description: 'Maximum asking price filter',
    example: 1000,
  })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  maxPrice?: number;

  @ApiPropertyOptional({
    description: 'Partial username search (case-insensitive)',
    example: 'alice',
  })
  @IsOptional()
  @IsString()
  username?: string;

  @ApiPropertyOptional({
    description: 'Filter by listing status. Default: active',
    enum: MarketplaceListingStatus,
    example: MarketplaceListingStatus.ACTIVE,
  })
  @IsOptional()
  @IsEnum(MarketplaceListingStatus)
  status?: MarketplaceListingStatus = MarketplaceListingStatus.ACTIVE;

  @ApiPropertyOptional({
    description: 'Sort field and direction',
    enum: MarketplaceSortField,
    default: MarketplaceSortField.NEWEST,
    example: MarketplaceSortField.NEWEST,
  })
  @IsOptional()
  @IsEnum(MarketplaceSortField)
  sort?: MarketplaceSortField = MarketplaceSortField.NEWEST;
}
