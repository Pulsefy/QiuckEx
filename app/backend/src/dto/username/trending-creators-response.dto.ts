import { ApiProperty } from '@nestjs/swagger';
import { PublicProfileDto } from './public-profile.dto';

/**
 * DTO for trending creators response
 */
export class TrendingCreatorsResponseDto {
  @ApiProperty({
    description: 'List of trending creator profiles sorted by volume',
    type: [PublicProfileDto],
  })
  creators: PublicProfileDto[];

  @ApiProperty({
    description: 'Time window used for trending calculation (hours)',
    example: 24,
  })
  timeWindowHours: number;

  @ApiProperty({
    description: 'Timestamp when trending was calculated',
    example: '2025-03-27T10:30:00Z',
  })
  calculatedAt: string;
}
