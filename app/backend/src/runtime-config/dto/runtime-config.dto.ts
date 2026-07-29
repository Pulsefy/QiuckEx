import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class NetworkConfigDto {
  @ApiProperty({ example: 'testnet', enum: ['testnet', 'mainnet'] })
  network: 'testnet' | 'mainnet';

  @ApiProperty({ example: 'Test SDF Network ; September 2015' })
  networkPassphrase: string;

  @ApiProperty({ example: 'https://horizon-testnet.stellar.org' })
  horizonUrl: string;

  @ApiProperty({ example: 'https://soroban-testnet.stellar.org' })
  sorobanRpcUrl: string;

  @ApiProperty({ example: ['https://soroban-testnet.stellar.org'] })
  sorobanRpcUrls: string[];

  @ApiProperty({ example: 'https://stellar.expert/explorer/testnet' })
  explorerUrl: string;
}

export class ContractEntryDto {
  @ApiProperty({ example: 'CD2J6K7T3YJ77QXZP3EXAMPLE' })
  contractId: string;

  @ApiProperty({ example: '0xabcdef1234567890' })
  wasmHash: string;

  @ApiProperty({ example: 1 })
  version: number;

  @ApiProperty({ example: '1.0.0' })
  schemaVersion: string;
}

export class FeatureFlagEntryDto {
  @ApiProperty({ example: 'bulk_invoicing_v2' })
  key: string;

  @ApiProperty({ example: 'Bulk Invoicing v2' })
  name: string;

  @ApiProperty({ example: true })
  enabled: boolean;

  @ApiProperty({ example: false })
  killSwitch: boolean;

  @ApiProperty({ example: 100, minimum: 0, maximum: 100 })
  rolloutPercentage: number;
}

export class PreviewMetadataDto {
  @ApiProperty({ example: 'pr-123' })
  scopeId: string;

  @ApiPropertyOptional({ example: 'feature/new-ui' })
  branchName?: string;

  @ApiProperty({ example: '2026-07-30T00:38:00.000Z' })
  expiresAt: string;

  @ApiProperty({ example: true })
  valid: boolean;
}

export class RuntimeConfigResponseDto {
  @ApiProperty({ example: 'production', enum: ['development', 'staging', 'production', 'test'] })
  environment: string;

  @ApiProperty({ type: NetworkConfigDto })
  network: NetworkConfigDto;

  @ApiProperty({ example: 'https://api.quickex.to' })
  apiUrl: string;

  @ApiProperty({ example: '0.1.0' })
  appVersion: string;

  @ApiProperty({ example: '0.1.0' })
  minAppVersion: string;

  @ApiProperty({
    type: 'object',
    description: 'Map of contract name to deployment metadata',
    example: {
      quickex: {
        contractId: 'CD2J6K7T3YJ77QXZP3EXAMPLE',
        wasmHash: '0xabcdef1234567890',
        version: 1,
        schemaVersion: '1.0.0',
      },
    },
  })
  contracts: Record<string, ContractEntryDto>;

  @ApiProperty({ type: [FeatureFlagEntryDto] })
  featureFlags: FeatureFlagEntryDto[];

  @ApiPropertyOptional({ type: PreviewMetadataDto })
  preview?: PreviewMetadataDto;

  @ApiProperty({ example: '2026-07-29T00:38:00.000Z' })
  generatedAt: string;

  @ApiProperty({ example: 'W/"runtime-config-1"' })
  etag: string;
}
