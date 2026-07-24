import { IsString, IsUrl, IsBoolean, IsOptional, IsEnum, IsInt, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateBranchPreviewRequestDto {
  @ApiProperty({ description: 'Git branch name', example: 'feature/new-payment-flow' })
  @IsString()
  branchName: string;

  @ApiProperty({ description: 'Preview environment API URL', example: 'https://api-preview-feature-123.example.com' })
  @IsUrl()
  apiUrl: string;

  @ApiProperty({ description: 'Preview environment frontend URL', example: 'https://preview-feature-123.example.com' })
  @IsUrl()
  frontendUrl: string;

  @ApiProperty({ description: 'Stellar network', enum: ['testnet', 'mainnet'], example: 'testnet' })
  @IsEnum(['testnet', 'mainnet'])
  network: 'testnet' | 'mainnet';

  @ApiProperty({ description: 'Contract registry version deployed', example: 'v1.2.3' })
  @IsString()
  contractRegistryVersion: string;

  @ApiProperty({ description: 'Time to live in milliseconds (optional)', required: false, example: 604800000 })
  @IsOptional()
  @IsInt()
  @Min(0)
  ttlMs?: number;
}

export class UpdateBranchPreviewRequestDto {
  @ApiProperty({ description: 'Updated API URL', required: false })
  @IsOptional()
  @IsUrl()
  apiUrl?: string;

  @ApiProperty({ description: 'Updated frontend URL', required: false })
  @IsOptional()
  @IsUrl()
  frontendUrl?: string;

  @ApiProperty({ description: 'Updated network', required: false, enum: ['testnet', 'mainnet'] })
  @IsOptional()
  @IsEnum(['testnet', 'mainnet'])
  network?: 'testnet' | 'mainnet';

  @ApiProperty({ description: 'Updated contract registry version', required: false })
  @IsOptional()
  @IsString()
  contractRegistryVersion?: string;

  @ApiProperty({ description: 'Whether the preview is active', required: false })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiProperty({ description: 'Updated TTL in milliseconds', required: false })
  @IsOptional()
  @IsInt()
  @Min(0)
  ttlMs?: number;
}