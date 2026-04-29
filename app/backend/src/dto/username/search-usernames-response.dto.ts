import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
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

  @ApiPropertyOptional({
    description: 'Opaque cursor to fetch the next page',
    nullable: true,
  })
  next_cursor: string | null;

  @ApiProperty({
    description: 'Whether more results exist beyond this page',
  })
  has_more: boolean;
}
