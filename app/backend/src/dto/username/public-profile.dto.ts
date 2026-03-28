import { ApiProperty } from '@nestjs/swagger';

/**
 * DTO representing a public user profile
 */
export class PublicProfileDto {
  @ApiProperty({
    description: 'Unique identifier for the username',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  id: string;

  @ApiProperty({
    description: 'Username (normalized, lowercase)',
    example: 'alice',
  })
  username: string;

  @ApiProperty({
    description: 'Stellar public key of the profile owner',
    example: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
  })
  publicKey: string;

  @ApiProperty({
    description: 'Similarity score for search results (0-100)',
    example: 95,
    required: false,
  })
  similarityScore?: number;

  @ApiProperty({
    description: 'Total transaction volume in the time period (for trending)',
    example: 15000.50,
    required: false,
  })
  transactionVolume?: number;

  @ApiProperty({
    description: 'Number of transactions in the time period (for trending)',
    example: 42,
    required: false,
  })
  transactionCount?: number;

  @ApiProperty({
    description: 'Last activity timestamp',
    example: '2025-03-27T10:30:00Z',
  })
  lastActiveAt: string;

  @ApiProperty({
    description: 'Username creation timestamp',
    example: '2025-02-19T08:00:00Z',
  })
  createdAt: string;
}
