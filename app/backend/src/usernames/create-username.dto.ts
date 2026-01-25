import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';

/**
 * DTO for creating a new username
 */
export class CreateUsernameDto {
  @ApiProperty({
    description: 'The username to register',
    example: 'alice_123',
    minLength: 3,
    maxLength: 32,
    pattern: '^[a-z0-9_]+$',
  })
  @IsString()
  @IsNotEmpty()
  @Length(3, 32)
  @Matches(/^[a-z0-9_]+$/, {
    message: 'Username must contain only lowercase letters, numbers, and underscores',
  })
  username!: string;

  @ApiProperty({
    description: "The user's Stellar public key",
    example: 'GBXGQ...7YWR',
  })
  @IsString()
  @IsNotEmpty()
  publicKey!: string;
}