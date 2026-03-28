import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsNumber, IsString, Min } from 'class-validator';
import { IsStellarPublicKey, IsUsername } from '../../dto/validators';

export class ListUsernameDto {
  @ApiProperty({ example: 'alice_123' })
  @IsString()
  @IsNotEmpty()
  @IsUsername({ message: 'Username must contain only lowercase letters, numbers, and underscores' })
  username!: string;

  @ApiProperty({ example: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR' })
  @IsString()
  @IsNotEmpty()
  @IsStellarPublicKey({ message: 'Public key must be a valid Stellar public key' })
  sellerPublicKey!: string;

  @ApiProperty({ description: 'Asking price in XLM', example: 100.5 })
  @IsNumber()
  @Min(0.0000001)
  askingPrice!: number;
}
