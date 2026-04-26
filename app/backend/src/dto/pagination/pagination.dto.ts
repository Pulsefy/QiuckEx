import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsInt, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';
import { PAGINATION_DEFAULTS } from '../../common/pagination/cursor.util';

/**
 * Standard query DTO for cursor-based pagination.
 * All list endpoints should accept these parameters.
 */
export class CursorPaginationQueryDto {
  @ApiPropertyOptional({
    description: 'Opaque cursor for the next page of results',
    example: 'eyJwayI6IjIwMjYtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImlkIjoiMTIzNDU2NzgtYWJjZC0xMjM0LTEyMzQtMTIzNDU2Nzg5MGFiIn0',
  })
  @IsOptional()
  @IsString()
  cursor?: string;

  @ApiPropertyOptional({
    description: 'Maximum number of items to return per page',
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
}

/**
 * Standard pagination metadata included in every cursor-paginated response.
 */
export class PaginationMetaDto {
  @ApiPropertyOptional({
    description: 'Opaque cursor to fetch the next page. Null if no more results.',
    example: 'eyJwayI6IjIwMjYtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImlkIjoiMTIzNDU2NzgtYWJjZC0xMjM0LTEyMzQtMTIzNDU2Nzg5MGFiIn0',
    nullable: true,
  })
  next_cursor: string | null;

  @ApiProperty({
    description: 'Whether there are more results beyond this page',
    example: true,
  })
  has_more: boolean;

  @ApiProperty({
    description: 'The limit used for this page',
    example: 20,
  })
  limit: number;
}

/**
 * Helper to build a standard paginated response envelope.
 */
export function paginatedResponse<T>(
  data: T[],
  nextCursor: string | null,
  hasMore: boolean,
  limit: number,
): { data: T[]; pagination: PaginationMetaDto } {
  const pagination = new PaginationMetaDto();
  pagination.next_cursor = nextCursor;
  pagination.has_more = hasMore;
  pagination.limit = limit;
  return { data, pagination };
}
