import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class AssetBrandingDto {
  @ApiPropertyOptional({ description: 'Asset logo URL (larger image)' })
  logo?: string;

  @ApiPropertyOptional({ description: 'Asset icon URL (small icon)' })
  icon?: string;

  @ApiPropertyOptional({ description: 'Asset description' })
  description?: string;

  @ApiPropertyOptional({ description: 'Full asset name' })
  name?: string;

  @ApiPropertyOptional({ description: 'Conditions for using the asset' })
  conditions?: string;

  @ApiPropertyOptional({ description: 'Whether asset is anchored' })
  isAssetAnchored?: boolean;

  @ApiPropertyOptional({ description: 'Anchor asset type' })
  anchorAssetType?: string;

  @ApiPropertyOptional({ description: 'Anchor asset identifier' })
  anchorAsset?: string;

  @ApiPropertyOptional({ description: 'Attestation of reserve URL' })
  attestationOfReserve?: string;

  @ApiPropertyOptional({ description: 'Redemption instructions' })
  redemptionInstructions?: string;
}

export class AssetMetadataResponseDto {
  @ApiProperty({ description: 'Asset code (e.g., USDC)' })
  code: string;

  @ApiProperty({ description: 'Asset type' })
  type: 'native' | 'credit_alphanum4' | 'credit_alphanum12';

  @ApiPropertyOptional({ description: 'Asset issuer public key' })
  issuer?: string;

  @ApiProperty({ description: 'Whether asset is verified' })
  verified: boolean;

  @ApiProperty({ description: 'Number of decimal places' })
  decimals: number;

  @ApiPropertyOptional({ description: 'Asset branding information' })
  branding?: AssetBrandingDto;

  @ApiProperty({ description: 'Whether using fallback branding' })
  isFallback: boolean;

  @ApiProperty({ description: 'Last updated timestamp' })
  updatedAt: string;
}

export class AssetListResponseDto {
  @ApiProperty({ description: 'List of assets with metadata', type: [AssetMetadataResponseDto] })
  assets: AssetMetadataResponseDto[];

  @ApiProperty({ description: 'Total number of assets' })
  total: number;
}
