import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class NetworkConfigDto {
  @ApiProperty({ example: 'testnet' })
  network: string;

  @ApiProperty({ example: 'Test SDF Network ; September 2015' })
  network_passphrase: string;
}

export class ContractRegistryEntryDto {
  @ApiProperty({ example: 'quickex' })
  name: string;

  @ApiProperty({ example: 'CD2J6K7T3YJ77QXZP3EXAMPLE' })
  contract_id: string;

  @ApiProperty({ example: 3 })
  version: number;

  @ApiProperty({ example: 'abcdef1234567890...' })
  wasm_hash: string;

  @ApiProperty({ example: '2026-06-01T10:00:00Z' })
  updated_at: string;
}

export class ContractRegistrySnapshotDto {
  @ApiProperty({ type: [ContractRegistryEntryDto] })
  active_contracts: ContractRegistryEntryDto[];
}

export class CheckpointDto {
  @ApiProperty({ example: 'CD2J6K7T3YJ77QXZP3EXAMPLE' })
  contract_id: string;

  @ApiProperty({ example: 49999500 })
  last_ledger: number;

  @ApiProperty({ example: '2026-06-02T12:30:00Z' })
  updated_at: string;
}

export class IndexerStatusDto {
  @ApiProperty({ example: 50000000 })
  current_network_ledger: number;

  @ApiProperty({ example: 49999500 })
  last_indexed_ledger: number;

  @ApiProperty({ example: 500 })
  lag_ledgers: number;

  @ApiProperty({ example: false })
  is_lagging: boolean;

  @ApiProperty({ example: 'HEALTHY', enum: ['HEALTHY', 'LAGGING', 'DISABLED', 'UNKNOWN'] })
  status: string;
}

export class RecentErrorDto {
  @ApiProperty({ example: '2026-06-02T12:20:00Z' })
  timestamp: string;

  @ApiProperty({ example: 'escrow.deposit' })
  action: string;

  @ApiProperty({ example: '[REDACTED]' })
  actor: string;

  @ApiProperty({ example: 'Insufficient balance' })
  error_summary: string;

  @ApiPropertyOptional({ example: 'req-12345' })
  request_id?: string;
}

export class SupportBundleMetadataDto {
  @ApiProperty({ example: '1.0' })
  version: string;

  @ApiProperty({ example: '2026-06-02T12:34:56Z' })
  generated_at: string;

  @ApiProperty({ example: 'testnet' })
  network: string;

  @ApiProperty({ example: 12345 })
  bundle_size_bytes: number;
}

export class SupportBundleDto {
  @ApiProperty()
  metadata: SupportBundleMetadataDto;

  @ApiProperty()
  network_config: NetworkConfigDto;

  @ApiProperty()
  contract_registry: ContractRegistrySnapshotDto;

  @ApiProperty()
  indexer_status: IndexerStatusDto;

  @ApiProperty({ type: [CheckpointDto] })
  checkpoints: CheckpointDto[];

  @ApiProperty({ type: [RecentErrorDto] })
  recent_errors: RecentErrorDto[];
}
