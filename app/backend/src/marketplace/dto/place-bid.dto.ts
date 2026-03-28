import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsNumber, IsString, Min } from 'class-validator';
import { IsStellarPublicKey } from '../../dto/validators';

export class PlaceBidDto {
  @ApiProperty({ example: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR' })
  @IsString()
  @IsNotEmpty()
  @IsStellarPublicKey({ message: 'Public key must be a valid Stellar public key' })
  bidderPublicKey!: string;

  @ApiProperty({ description: 'Bid amount in XLM', example: 90.0 })
  @IsNumber()
  @Min(0.0000001)
  bidAmount!: number;
}
