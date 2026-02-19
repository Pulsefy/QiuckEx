import { ApiProperty } from '@nestjs/swagger';

export class UsernameItemDto {
  @ApiProperty({ description: 'Unique record id', example: '550e8400-e29b-41d4-a716-446655440000' })
  id!: string;

  @ApiProperty({ description: 'Username (normalized lowercase)', example: 'alice_123' })
  username!: string;

  @ApiProperty({ description: 'Stellar public key of the owner' })
  public_key!: string;

  @ApiProperty({ description: 'ISO 8601 creation time' })
  created_at!: string;
}

/**
 * Response DTO for listing usernames by wallet.
 */
export class ListUsernamesResponseDto {
  @ApiProperty({
    description: 'Usernames registered for the given wallet',
    type: [UsernameItemDto],
  })
  usernames!: UsernameItemDto[];
}
