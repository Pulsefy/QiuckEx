import { ApiProperty } from '@nestjs/swagger';
import { 
  IsString, 
  IsUrl, 
  IsBoolean, 
  IsArray, 
  ValidateNested, 
  IsObject 
} from 'class-validator';
import { Type } from 'class-transformer';

export class NetworkConfigDto {
  @ApiProperty({ description: 'The current network environment (e.g., testnet, preview)' })
  @IsString()
  environment: string;

  @ApiProperty({ description: 'Soroban RPC Endpoint' })
  @IsUrl()
  rpcUrl: string;

  @ApiProperty({ description: 'Stellar Horizon Endpoint' })
  @IsUrl()
  horizonUrl: string;

  @ApiProperty({ description: 'Stellar Network Passphrase' })
  @IsString()
  networkPassphrase: string;
}

export class ContractConfigDto {
  @ApiProperty({ description: 'Address of the Contract Registry' })
  @IsString()
  registryId: string;

  @ApiProperty({ description: 'Address of the Router Contract' })
  @IsString()
  routerId: string;

  @ApiProperty({ description: 'List of allowed token addresses', type: [String] })
  @IsArray()
  @IsString({ each: true })
  allowedTokens: string[];
}

export class BackendMetadataDto {
  @ApiProperty({ description: 'Current backend API version' })
  @IsString()
  version: string;

  @ApiProperty({ description: 'Base URL for the API' })
  @IsUrl()
  apiUrl: string;

  @ApiProperty({ description: 'Key-value pairs for active feature flags' })
  @IsObject()
  featureFlags: Record<string, boolean>;
}

export class BootstrapResponseDto {
  @ApiProperty({ type: NetworkConfigDto })
  @ValidateNested()
  @Type(() => NetworkConfigDto)
  network: NetworkConfigDto;

  @ApiProperty({ type: ContractConfigDto })
  @ValidateNested()
  @Type(() => ContractConfigDto)
  contracts: ContractConfigDto;

  @ApiProperty({ type: BackendMetadataDto })
  @ValidateNested()
  @Type(() => BackendMetadataDto)
  backendMetadata: BackendMetadataDto;
}