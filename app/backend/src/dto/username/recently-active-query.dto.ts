import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsInt, Min, Max } from 'class-validator';

/**
 * DTO for recently active users query parameters
 */
export class RecentlyActiveQueryDto {
  @ApiProperty({
    description: 'Time window in hours to consider users as recently active',
    example: 24,
    required: false,
    default: 24,
  })
  @IsInt()
  @Min(1)
  @Max(168) // Max 7 days
  @Type(() => Number)
  timeWindowHours?: number = 24;

  @ApiProperty({
    description: 'Maximum number of recently active users to return',
    example: 10,
    required: false,
    default: 10,
  })
  @IsInt()
  @Min(1)
  @Max(100)
  @Type(() => Number)
  limit?: number = 10;
}
