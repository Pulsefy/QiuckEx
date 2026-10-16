import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  Max,
  Min,
  ValidateNested,
} from 'class-validator';

import { ContractSchemaCompatibilityDto } from './contract-registry.dto';

export type ContractCompatibilityFlow = 'link' | 'quote' | 'pay_initiation';

export class FlowCompatibilityRequirementDto {
  @ApiProperty({
    example: 'pay_initiation',
    enum: ['link', 'quote', 'pay_initiation'],
  })
  flow!: ContractCompatibilityFlow;

  @ApiProperty({ example: 'quickex' })
  contractName!: string;

  @ApiProperty({ example: 1 })
  minContractVersion!: number;

  @ApiProperty({ example: 100000 })
  maxContractVersion!: number;

  @ApiProperty({ type: ContractSchemaCompatibilityDto })
  schemaCompatibility!: ContractSchemaCompatibilityDto;

  @ApiProperty({
    example: ['deposit', 'deposit_with_commitment', 'deposit_partial', 'withdraw', 'refund'],
    type: [String],
  })
  supportedWriteMethods!: string[];
}

export class ContractTransitionMetadataDto {
  @ApiProperty({ example: true })
  active!: boolean;

  @ApiPropertyOptional({ example: 'CD2J6K7T3YJ77QXZP3OLDEXAMPLE' })
  previousContractId?: string;

  @ApiPropertyOptional({ example: 47000000 })
  effectiveLedger?: number;

  @ApiPropertyOptional({ example: '2026-06-02T12:00:00Z' })
  effectiveTime?: string;
}

export class ContractCompatibilityMetadataDto {
  @ApiProperty({ example: 'quickex' })
  contractName!: string;

  @ApiProperty({ example: 'testnet' })
  network!: string;

  @ApiProperty({ example: 'CD2J6K7T3YJ77QXZP3EXAMPLE' })
  contractId!: string;

  @ApiProperty({ example: '0xabcdef1234567890' })
  wasmHash!: string;

  @ApiProperty({ example: 1 })
  contractVersion!: number;

  @ApiProperty({ example: '1.0.0' })
  schemaVersion!: string;

  @ApiProperty({ type: ContractSchemaCompatibilityDto })
  schemaCompatibility!: ContractSchemaCompatibilityDto;

  @ApiProperty({
    example: 'pay_initiation',
    enum: ['link', 'quote', 'pay_initiation'],
  })
  flow!: ContractCompatibilityFlow;

  @ApiProperty({ type: FlowCompatibilityRequirementDto })
  requirements!: FlowCompatibilityRequirementDto;

  @ApiProperty({ example: true })
  compatible!: boolean;

  @ApiPropertyOptional({ type: ContractTransitionMetadataDto })
  transition?: ContractTransitionMetadataDto;
}

export class ClientContractAssertionDto {
  @ApiPropertyOptional({
    example: 1,
    description: 'Expected on-chain contract deployment version asserted by the client',
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100_000)
  contractVersion?: number;

  @ApiPropertyOptional({
    example: '1.0.0',
    description: 'Client contract schema version (semver)',
  })
  @IsOptional()
  @IsString()
  @Matches(/^\d+\.\d+\.\d+$/, {
    message: 'schemaVersion must be a valid semantic version (e.g. 1.0.0)',
  })
  schemaVersion?: string;

  @ApiPropertyOptional({
    example: 'CD2J6K7T3YJ77QXZP3EXAMPLE',
    description: 'Target contract ID asserted by the client',
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  contractId?: string;
}

export class ValidateWriteCompatibilityDto extends ClientContractAssertionDto {
  @ApiPropertyOptional({ example: 'quickex', default: 'quickex' })
  @IsOptional()
  @IsString()
  contractName?: string;

  @ApiPropertyOptional({ example: 'deposit' })
  @IsOptional()
  @IsString()
  method?: string;

  @ApiPropertyOptional({
    example: 'pay_initiation',
    enum: ['link', 'quote', 'pay_initiation'],
  })
  @IsOptional()
  @IsString()
  flow?: ContractCompatibilityFlow;

  @ApiPropertyOptional({ type: ClientContractAssertionDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ClientContractAssertionDto)
  assertion?: ClientContractAssertionDto;
}
