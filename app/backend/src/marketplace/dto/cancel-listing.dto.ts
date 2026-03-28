import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';
import { IsStellarPublicKey } from '../../dto/validators';

export class CancelListingDto {
  @ApiProperty({ example: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR' })
  @IsString()
  @IsNotEmpty()
  @IsStellarPublicKey({ message: 'Public key must be a valid Stellar public key' })
  sellerPublicKey!: string;
}
