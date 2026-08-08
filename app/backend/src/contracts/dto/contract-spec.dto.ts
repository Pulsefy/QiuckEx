import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ContractMethodDto {
  @ApiProperty({ example: 'create_payment_link' })
  name: string;

  @ApiProperty({
    example: ['address', 'amount', 'asset_code', 'memo'],
    description: 'Method arguments in order with their types',
  })
  args: string[];

  @ApiProperty({
    example: 'bool',
    description: 'Return type of the method',
  })
  returns: string;

  @ApiPropertyOptional({ example: 'Creates a new payment link' })
  description?: string;

  @ApiPropertyOptional({
    example: { admin: true, public: true },
    description: 'Access control metadata for the method',
  })
  access?: Record<string, boolean>;
}

export class ContractEventDto {
  @ApiProperty({ example: 'PaymentLinkCreated' })
  name: string;

  @ApiProperty({
    example: ['link_id', 'amount', 'asset_code'],
    description: 'Event fields with their types',
  })
  fields: string[];

  @ApiPropertyOptional({ example: 'Emitted when a new payment link is created' })
  description?: string;
}

export class ContractStorageDto {
  @ApiProperty({ example: 'Escrow' })
  name: string;

  @ApiProperty({
    example: ['id', 'depositor', 'beneficiary', 'amount'],
    description: 'Storage fields with their types',
  })
  fields: string[];

  @ApiPropertyOptional({ example: 'Contains escrow records with deposit and release information' })
  description?: string;
}

export class ContractSpecResponseDto {
  @ApiProperty({ example: 'quickex' })
  name: string;

  @ApiProperty({ example: 'CD2J6K7T3YJ77QXZP3EXAMPLE' })
  contractId: string;

  @ApiProperty({ example: '0xabcdef1234567890' })
  wasmHash: string;

  @ApiProperty({ example: 1 })
  version: number;

  @ApiProperty({ example: '1.0.0' })
  schemaVersion: string;

  @ApiProperty({ type: [ContractMethodDto] })
  methods: ContractMethodDto[];

  @ApiProperty({ type: [ContractEventDto] })
  events: ContractEventDto[];

  @ApiProperty({ type: [ContractStorageDto] })
  storage: ContractStorageDto[];

  @ApiPropertyOptional({
    example: {
      author: 'QuickEx Team',
      license: 'MIT',
      source: 'https://github.com/quickex/contract',
    },
  })
  metadata?: Record<string, unknown>;

  @ApiProperty({ example: '2026-08-05T12:00:00Z' })
  updatedAt: string;

  @ApiProperty({ example: 'W/"contract-spec-quickex-1"' })
  etag: string;
}

export class ContractSpecsResponseDto {
  @ApiProperty({ example: 'testnet' })
  network: string;

  @ApiProperty({ example: 'W/"contract-specs-2"' })
  etag: string;

  @ApiProperty({ example: 2 })
  version: number;

  @ApiProperty({
    type: 'object',
    additionalProperties: { $ref: '#/components/schemas/ContractSpecResponseDto' },
  })
  specs: Record<string, ContractSpecResponseDto>;
}

export class StoreContractSpecDto {
  @ApiProperty({ example: 'quickex' })
  name: string;

  @ApiProperty({ type: [ContractMethodDto] })
  methods: ContractMethodDto[];

  @ApiProperty({ type: [ContractEventDto] })
  events: ContractEventDto[];

  @ApiProperty({ type: [ContractStorageDto] })
  storage: ContractStorageDto[];

  @ApiPropertyOptional({ example: { author: 'QuickEx Team' } })
  metadata?: Record<string, unknown>;
}