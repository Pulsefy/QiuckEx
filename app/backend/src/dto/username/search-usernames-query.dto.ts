import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString, Min, Max, IsInt } from 'class-validator';
import { Type } from 'class-transformer';

/**
 * DTO for searching public usernames with fuzzy matching
 */
export class SearchUsernamesQueryDto {
  @ApiProperty({
    description: 'Search query for fuzzy matching',
    example: 'alice',
    required: true,
  })
  @IsString()
  query: string;

  @ApiProperty({
    description: 'Maximum number of results to return',
    example: 10,
    required: false,
    default: 10,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  @Type(() => Number)
  limit?: number = 10;
}
