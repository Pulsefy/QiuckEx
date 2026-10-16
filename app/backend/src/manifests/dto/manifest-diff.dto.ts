import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsObject, IsOptional, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class ManifestContractDto {
  @ApiProperty({ description: 'Contract ID', example: 'CA...' })
  id: string;

  @ApiProperty({ description: 'WASM bytecode hash', example: 'abc123...' })
  wasmHash: string;
}

export class EnvironmentManifestDto {
  @ApiPropertyOptional({ description: 'Contracts map', type: Object })
  @IsOptional()
  @IsObject()
  contracts?: Record<string, ManifestContractDto>;

  @ApiPropertyOptional({ description: 'URLs map', type: Object })
  @IsOptional()
  @IsObject()
  urls?: Record<string, string>;

  @ApiPropertyOptional({ description: 'Feature flags map', type: Object })
  @IsOptional()
  @IsObject()
  featureFlags?: Record<string, boolean>;
}

export class CompareManifestsDto {
  @ApiProperty({ description: 'Base environment manifest', type: EnvironmentManifestDto })
  @ValidateNested()
  @Type(() => EnvironmentManifestDto)
  baseManifest: EnvironmentManifestDto;

  @ApiProperty({ description: 'Target environment manifest', type: EnvironmentManifestDto })
  @ValidateNested()
  @Type(() => EnvironmentManifestDto)
  targetManifest: EnvironmentManifestDto;
}

export class ManifestDiffResponseDto {
  @ApiProperty({ description: 'Contracts diff map', type: Object })
  contracts: Record<string, { status: string; oldValue?: ManifestContractDto; newValue?: ManifestContractDto }>;

  @ApiProperty({ description: 'URLs diff map', type: Object })
  urls: Record<string, { status: string; oldValue?: string; newValue?: string }>;

  @ApiProperty({ description: 'Feature flags diff map', type: Object })
  featureFlags: Record<string, { status: string; oldValue?: boolean; newValue?: boolean }>;
}

