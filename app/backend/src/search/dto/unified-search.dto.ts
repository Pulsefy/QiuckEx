import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsInt, IsOptional, IsString, Max, Min, IsIn } from 'class-validator';
import { PublicProfileDto } from '../../dto/username/public-profile.dto';

export class SearchListingDto {
  @ApiProperty({ description: 'Listing ID', example: '550e8400-e29b-41d4-a716-446655440000' })
  id: string;

  @ApiProperty({ description: 'Username being listed', example: 'pay' })
  username: string;

  @ApiProperty({ description: 'Seller public key', example: 'GDRH...4T9F' })
  sellerPublicKey: string;

  @ApiProperty({ description: 'Asking price in XLM', example: '12000' })
  askingPrice: string;

  @ApiProperty({ description: 'Current status', example: 'active' })
  status: string;

  @ApiPropertyOptional({ description: 'Listing category', example: 'og' })
  category?: string;

  @ApiProperty({ description: 'Creation timestamp', example: '2026-02-01T00:00:00Z' })
  createdAt: string;
}

export class UnifiedSearchQueryDto {
  @ApiProperty({
    description: 'Search query for fuzzy matching (min 2 characters)',
    example: 'alice',
  })
  @IsString()
  q: string;

  @ApiPropertyOptional({
    description: 'Filter search by type (all, profiles, listings)',
    example: 'all',
    enum: ['all', 'profiles', 'listings'],
  })
  @IsOptional()
  @IsIn(['all', 'profiles', 'listings'])
  type?: 'all' | 'profiles' | 'listings' = 'all';

  @ApiPropertyOptional({
    description: 'Maximum number of results per section (1-50)',
    example: 10,
    default: 10,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(50)
  limit?: number = 10;
}

export class UnifiedSearchResponseDto {
  @ApiProperty({ description: 'Original search query', example: 'alise' })
  query: string;

  @ApiPropertyOptional({
    description: 'Typo-tolerant suggestion if minor misspelling detected',
    example: 'alice',
    nullable: true,
  })
  didYouMean?: string | null;

  @ApiProperty({
    description: 'Matching public user profiles',
    type: [PublicProfileDto],
  })
  profiles: PublicProfileDto[];

  @ApiProperty({
    description: 'Matching marketplace listings',
    type: [SearchListingDto],
  })
  listings: SearchListingDto[];

  @ApiProperty({ description: 'Total profiles found', example: 3 })
  totalProfiles: number;

  @ApiProperty({ description: 'Total listings found', example: 2 })
  totalListings: number;
}
