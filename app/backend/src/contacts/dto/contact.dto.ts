import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsArray, IsNotEmpty, IsOptional, IsString, IsUUID, MaxLength, ValidateNested } from 'class-validator';
import { IsStellarPublicKey } from '../../dto/validators';

export class ContactDto {
  @ApiPropertyOptional({ format: 'uuid' })
  @IsOptional()
  @IsUUID()
  id?: string;

  @ApiProperty({ example: 'GABC...' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  address!: string;

  @ApiProperty({ example: 'Alice' })
  @IsString()
  @MaxLength(120)
  nickname!: string;

  @ApiPropertyOptional({ example: ['Friends'] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];
}

export class ContactOwnerDto {
  @ApiProperty({ example: 'GABC...' })
  @IsString()
  @IsNotEmpty()
  @IsStellarPublicKey({ message: 'Owner public key must be a valid Stellar public key' })
  ownerPublicKey!: string;
}

export class CreateContactDto extends ContactOwnerDto {
  @ApiProperty({ type: ContactDto })
  @ValidateNested()
  @Type(() => ContactDto)
  contact!: ContactDto;
}

export class UpdateContactDto extends ContactOwnerDto {
  @ApiProperty({ type: ContactDto })
  @ValidateNested()
  @Type(() => ContactDto)
  contact!: ContactDto;
}
