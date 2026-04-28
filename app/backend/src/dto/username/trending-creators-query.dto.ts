import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsInt, IsOptional, IsString, Min, Max } from 'class-validator';

/**
 * DTO for trending creators query parameters
 */
export class TrendingCreatorsQueryDto {
  @ApiProperty({
    description: 'Time window in hours for trending calculation',
    example: 24,
    required: false,
    default: 24,
  })
  @IsInt()
  @Min(1)
  @Max(720) // Max 30 days
  @Type(() => Number)
  timeWindowHours?: number = 24;

  @ApiProperty({
    description: 'Maximum number of trending creators to return',
    example: 10,
    required: false,
    default: 10,
  })
  @IsInt()
  @Min(1)
  @Max(100)
  @Type(() => Number)
  limit?: number = 10;

  @ApiProperty({
    description: 'Opaque cursor for the next page of results',
    required: false,
  })
  @IsOptional()
  @IsString()
  cursor?: string;
}
