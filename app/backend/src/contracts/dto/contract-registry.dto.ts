import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsBoolean,
  IsInt,
  IsISO8601,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  Matches,
  Max,
  Min,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

export class ContractRegistryEntryDto {
  @ApiProperty({ example: 'quickex' })
  @IsString()
  @IsNotEmpty()
  @Matches(/^[a-z0-9_-]+$/i)
  name: string;

  @ApiProperty({ example: 'CD2J6K7T3YJ77QXZP3EXAMPLE' })
  @IsString()
  @IsNotEmpty()
  contractId: string;

  @ApiPropertyOptional({
    example: 'CD2J6K7T3YJ77QXZP3OLDEXAMPLE',
    description: 'Previous contract ID for dual-read during transition window',
  })
  @IsOptional()
  @IsString()
  previousContractId?: string;

  @ApiPropertyOptional({
    example: 47_000_000,
    description: 'Ledger number after which to stop reading from previous contract ID',
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  effectiveLedger?: number;

  @ApiPropertyOptional({
    example: '2026-06-02T12:00:00Z',
    description: 'ISO 8601 timestamp after which to stop reading from previous contract ID',
  })
  @IsOptional()
  @IsISO8601()
  effectiveTime?: string;

  @ApiProperty({ example: 'abcdef1234567890' })
  @IsString()
  @IsNotEmpty()
  wasmHash: string;

  @ApiPropertyOptional({ example: 1, default: 1 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100_000)
  contractVersion?: number;

  @ApiPropertyOptional({ example: { source: 'testnet-deploy' } })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;
}

export class PublishContractRegistryDto {
  @ApiProperty({ example: 'Test SDF Network ; September 2015' })
  @IsString()
  @IsNotEmpty()
  networkPassphrase: string;

  @ApiPropertyOptional({ example: 'deploy-2026-05-30T18:00:00Z' })
  @IsOptional()
  @IsString()
  deploymentId?: string;

  @ApiProperty({ type: [ContractRegistryEntryDto] })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(10)
  @ValidateNested({ each: true })
  @Type(() => ContractRegistryEntryDto)
  contracts: ContractRegistryEntryDto[];
}

export class RollbackContractRegistryDto {
  @ApiProperty({ example: 'quickex' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: 1 })
  @IsInt()
  @Min(1)
  version: number;
}

export class ContractRegistryResponseDto {
  @ApiProperty({ example: 'testnet' })
  network: string;

  @ApiProperty({ example: 'W/"contract-registry-testnet-2"' })
  etag: string;

  @ApiProperty({ example: 2 })
  version: number;

  @ApiProperty({ example: true })
  @IsBoolean()
  authoritative: boolean;

  @ApiProperty({
    example: {
      quickex: {
        id: 'CD2J6K7T3YJ77QXZP3EXAMPLE',
        wasmHash: 'abcdef1234567890',
        version: 1,
      },
    },
  })
  data: Record<string, unknown>;
}
