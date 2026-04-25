import { ApiProperty } from '@nestjs/swagger';
import { PublicProfileDto } from './public-profile.dto';

/**
 * DTO for recently active users response
 */
export class RecentlyActiveResponseDto {
  @ApiProperty({
    description: 'List of recently active public profiles sorted by last activity',
    type: [PublicProfileDto],
  })
  users: PublicProfileDto[];

  @ApiProperty({
    description: 'Time window used for recently active calculation (hours)',
    example: 24,
  })
  timeWindowHours: number;

  @ApiProperty({
    description: 'Timestamp when the list was calculated',
    example: '2025-03-27T10:30:00Z',
  })
  calculatedAt: string;
}
