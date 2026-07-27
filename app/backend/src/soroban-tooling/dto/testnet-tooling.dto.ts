import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  Min,
  ValidateNested,
} from 'class-validator';

export class FundingPreflightDto {
  @ApiProperty({ example: 'GABCD1234EXAMPLE' })
  @IsString()
  @IsNotEmpty()
  accountId: string;

  @ApiPropertyOptional({ example: 5, default: 5 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  minBalanceXlm?: number;
}

export class DeployContractSpecDto {
  @ApiProperty({ example: 'quickex' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: 'app/contract/target/wasm32-unknown-unknown/release/quickex.wasm' })
  @IsString()
  @IsNotEmpty()
  wasmPath: string;

  @ApiPropertyOptional({ example: 'initialize' })
  @IsOptional()
  @IsString()
  initMethod?: string;

  @ApiPropertyOptional({ example: ['GADMINEXAMPLE...'] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  initArgs?: string[];
}

export class DeploymentPlanDto {
  @ApiProperty({ example: 'testnet' })
  @IsString()
  @Matches(/^(testnet|mainnet)$/)
  network: 'testnet' | 'mainnet';

  @ApiProperty({ example: 'test' })
  @IsString()
  @IsNotEmpty()
  source: string;

  @ApiPropertyOptional({ example: true, default: true })
  @IsOptional()
  @IsBoolean()
  dryRun?: boolean;

  @ApiPropertyOptional({ example: true, default: true })
  @IsOptional()
  @IsBoolean()
  publishRegistry?: boolean;

  @ApiPropertyOptional({ example: 'GADMINEXAMPLE...' })
  @IsOptional()
  @IsString()
  adminPublicKey?: string;

  @ApiProperty({ type: [DeployContractSpecDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => DeployContractSpecDto)
  contracts: DeployContractSpecDto[];
}
