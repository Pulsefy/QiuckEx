import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsBoolean,
  IsIn,
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

export class ContractSchemaCompatibilityDto {
  @ApiProperty({ example: '1.0.0' })
  @IsString()
  @IsNotEmpty()
  @Matches(/^\d+\.\d+\.\d+$/)
  min: string;

  @ApiProperty({ example: '2.0.0' })
  @IsString()
  @IsNotEmpty()
  @Matches(/^\d+\.\d+\.\d+$/)
  max: string;
}

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

  @ApiProperty({ example: '0xabcdef1234567890' })
  @IsString()
  @IsNotEmpty()
  wasmHash: string;

  @ApiPropertyOptional({ example: 1, default: 1 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100_000)
  contractVersion?: number;

  @ApiPropertyOptional({ example: '1.2.0', description: 'Contract schema version' })
  @IsOptional()
  @IsString()
  @Matches(/^\d+\.\d+\.\d+$/)
  schemaVersion?: string;

  @ApiPropertyOptional({ type: ContractSchemaCompatibilityDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ContractSchemaCompatibilityDto)
  schemaCompatibility?: ContractSchemaCompatibilityDto;

  @ApiPropertyOptional({ example: { admin: 'G...' }, description: 'Deployment init params' })
  @IsOptional()
  @IsObject()
  initParams?: Record<string, unknown>;

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

export class UpsertContractDeploymentDto {
  @ApiProperty({ example: 'quickex' })
  @IsString()
  @IsNotEmpty()
  @Matches(/^[a-z0-9_-]+$/i)
  name: string;

  @ApiProperty({ example: 'testnet', enum: ['testnet', 'mainnet'] })
  @IsString()
  @IsIn(['testnet', 'mainnet'])
  network: 'testnet' | 'mainnet';

  @ApiProperty({ example: 'Test SDF Network ; September 2015' })
  @IsString()
  @IsNotEmpty()
  networkPassphrase: string;

  @ApiProperty({ example: 'CD2J6K7T3YJ77QXZP3EXAMPLE' })
  @IsString()
  @IsNotEmpty()
  contractId: string;

  @ApiProperty({ example: '0xabcdef1234567890' })
  @IsString()
  @IsNotEmpty()
  wasmHash: string;

  @ApiPropertyOptional({ example: 1, default: 1 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100_000)
  contractVersion?: number;

  @ApiProperty({ example: '1.2.0' })
  @IsString()
  @IsNotEmpty()
  @Matches(/^\d+\.\d+\.\d+$/)
  schemaVersion: string;

  @ApiProperty({ type: ContractSchemaCompatibilityDto })
  @ValidateNested()
  @Type(() => ContractSchemaCompatibilityDto)
  schemaCompatibility: ContractSchemaCompatibilityDto;

  @ApiPropertyOptional({ example: { admin: 'G...' } })
  @IsOptional()
  @IsObject()
  initParams?: Record<string, unknown>;

  @ApiPropertyOptional({ example: 'deploy-2026-05-30T18:00:00Z' })
  @IsOptional()
  @IsString()
  deploymentId?: string;

  @ApiPropertyOptional({ example: { source: 'manual-admin-upsert' } })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;
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
        wasmHash: '0xabcdef1234567890',
        version: 1,
        schemaVersion: '1.2.0',
        schemaCompatibility: {
          min: '1.0.0',
          max: '2.0.0',
        },
      },
    },
  })
  data: Record<string, unknown>;
}

export class ContractDeploymentItemDto {
  @ApiProperty({ example: 'quickex' })
  name: string;

  @ApiProperty({ example: 'testnet' })
  network: string;

  @ApiProperty({ example: 'Test SDF Network ; September 2015' })
  networkPassphrase: string;

  @ApiProperty({ example: 'CD2J6K7T3YJ77QXZP3EXAMPLE' })
  contractId: string;

  @ApiProperty({ example: '0xabcdef1234567890' })
  wasmHash: string;

  @ApiProperty({ example: 3 })
  contractVersion: number;

  @ApiProperty({ example: '1.2.0' })
  schemaVersion: string;

  @ApiProperty({ type: ContractSchemaCompatibilityDto })
  schemaCompatibility: ContractSchemaCompatibilityDto;

  @ApiPropertyOptional({ example: { admin: 'G...' } })
  initParams?: Record<string, unknown>;

  @ApiPropertyOptional({ example: { source: 'deploy-script' } })
  metadata?: Record<string, unknown>;

  @ApiProperty({ example: '2026-06-02T11:54:30Z' })
  updatedAt: string;

  @ApiProperty({ example: 8 })
  registryVersion: number;

  @ApiPropertyOptional({ example: 'deploy-2026-06-02T11:54:30Z' })
  deploymentId?: string;
}

export class ContractDeploymentsResponseDto {
  @ApiProperty({ example: 'testnet' })
  network: string;

  @ApiProperty({ type: [ContractDeploymentItemDto] })
  deployments: ContractDeploymentItemDto[];
}
