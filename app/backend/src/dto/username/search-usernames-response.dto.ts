import { ApiProperty } from '@nestjs/swagger';
import { PublicProfileDto } from './public-profile.dto';

/**
 * DTO for search usernames response
 */
export class SearchUsernamesResponseDto {
  @ApiProperty({
    description: 'List of public profiles matching the search query',
    type: [PublicProfileDto],
  })
  profiles: PublicProfileDto[];

  @ApiProperty({
    description: 'Total number of matching results',
    example: 42,
  })
  total: number;
}
