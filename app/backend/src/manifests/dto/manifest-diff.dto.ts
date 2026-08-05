import { IsObject, IsOptional, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class ManifestContractDto {
  id: string;
  wasmHash: string;
}

export class EnvironmentManifestDto {
  @IsOptional()
  @IsObject()
  contracts?: Record<string, ManifestContractDto>;

  @IsOptional()
  @IsObject()
  urls?: Record<string, string>;

  @IsOptional()
  @IsObject()
  featureFlags?: Record<string, boolean>;
}

export class CompareManifestsDto {
  @ValidateNested()
  @Type(() => EnvironmentManifestDto)
  baseManifest: EnvironmentManifestDto;

  @ValidateNested()
  @Type(() => EnvironmentManifestDto)
  targetManifest: EnvironmentManifestDto;
}
