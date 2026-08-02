import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { PublicProfileDto } from './public-profile.dto';

export class SearchDiscoveryResultDto {
  @ApiProperty({
    description: 'Kind of search result item',
    enum: ['profile', 'listing'],
    example: 'profile',
  })
  kind: 'profile' | 'listing';

  @ApiProperty({
    description: 'Unique identifier for the item',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  id: string;

  @ApiProperty({
    description: 'Username associated with the result',
    example: 'alice',
  })
  username: string;

  @ApiPropertyOptional({
    description: 'Public key for profile results',
    example: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
  })
  publicKey?: string;

  @ApiPropertyOptional({
    description: 'Seller public key for marketplace listing results',
    example: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
  })
  sellerPublicKey?: string;

  @ApiPropertyOptional({
    description: 'Similarity score used to rank the result',
    example: 95,
  })
  similarityScore?: number;

  @ApiPropertyOptional({
    description: 'Asking price for marketplace listing results',
    example: 250,
  })
  askingPrice?: number;

  @ApiPropertyOptional({
    description: 'Marketplace listing status',
    example: 'active',
  })
  status?: string;

  @ApiPropertyOptional({
    description: 'Last activity timestamp for profile results',
    example: '2025-03-27T10:30:00Z',
  })
  lastActiveAt?: string;

  @ApiProperty({
    description: 'Creation timestamp for the result',
    example: '2025-02-19T08:00:00Z',
  })
  createdAt: string;
}

/**
 * DTO for unified discovery search response
 */
export class SearchUsernamesResponseDto {
  @ApiProperty({
    description: 'Unified search results for profiles and marketplace listings',
    type: [SearchDiscoveryResultDto],
  })
  results: SearchDiscoveryResultDto[];

  @ApiPropertyOptional({
    description: 'Profile-only subset retained for backwards compatibility',
    type: [PublicProfileDto],
  })
  profiles?: PublicProfileDto[];

  @ApiProperty({
    description: 'Whether the current query produced no matches',
    example: false,
  })
  empty: boolean;

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
