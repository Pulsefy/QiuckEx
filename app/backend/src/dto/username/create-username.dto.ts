import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length } from 'class-validator';

import { IsUsername, IsStellarPublicKey } from '../validators';

/**
 * DTO for creating a new username
 * 
 * @example
 * ```json
 * {
 *   "username": "alice_123",
 *   "publicKey": "GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR"
 * }
 * ```
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
  @Length(3, 32, {
    message: 'Username must be between 3 and 32 characters',
  })
  @IsUsername({
    message: 'Username must contain only lowercase letters, numbers, and underscores',
  })
  username!: string;

  @ApiProperty({
    description: "The user's Stellar public key",
    example: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
  })
  @IsString()
  @IsNotEmpty()
  @IsStellarPublicKey({
    message: 'Public key must be a valid Stellar public key',
  })
  publicKey!: string;
}
