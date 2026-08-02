import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsInt, IsOptional, IsString, Min, Max } from 'class-validator';

/**
 * DTO for featured usernames query parameters
 */
export class FeaturedUsernamesQueryDto {
  @ApiProperty({
    description: 'Maximum number of featured usernames to return',
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
