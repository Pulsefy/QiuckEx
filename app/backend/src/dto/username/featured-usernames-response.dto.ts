import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { PublicProfileDto } from './public-profile.dto';

/**
 * DTO for featured usernames response
 */
export class FeaturedUsernamesResponseDto {
  @ApiProperty({
    description:
      'List of curated/featured public profiles ordered by featured rank',
    type: [PublicProfileDto],
  })
  profiles: PublicProfileDto[];

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
