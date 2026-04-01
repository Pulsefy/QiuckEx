/**
 * Asset metadata types for branding and TOML integration
 */

export interface AssetBranding {
  logo?: string;
  icon?: string;
  description?: string;
  name?: string;
  conditions?: string;
  is_asset_anchored?: boolean;
  anchor_asset_type?: string;
  anchor_asset?: string;
  attestation_of_reserve?: string;
  redemption_instructions?: string;
  collateral_addresses?: string[];
  collateral_address_signatures?: string[];
}

export interface CachedAssetMetadata {
  code: string;
  issuer: string | null;
  branding: AssetBranding;
  fetchedAt: Date;
  ttl: number;
}

export interface TomlCurrency {
  code: string;
  issuer?: string;
  status?: 'live' | 'dead' | 'test' | string;
  display_decimals?: number;
  name?: string;
  desc?: string;
  conditions?: string;
  image?: string;
  fixed_number?: number;
  max_number?: number;
  is_unlimited?: boolean;
  is_asset_anchored?: boolean;
  anchor_asset_type?: 'fiat' | 'crypto' | 'stock' | 'commodity' | 'realestate' | 'other' | string;
  anchor_asset?: string;
  attestation_of_reserve?: string;
  redemption_instructions?: string;
  collateral_addresses?: string[];
  collateral_address_signatures?: string[];
  regulated?: boolean;
  approval_server?: string;
  approval_criteria?: string;
}

export interface ParsedStellarToml {
  GENERAL_INFORMATION?: {
    issuer?: string;
    name?: string;
    desc?: string;
    image?: string;
    [key: string]: unknown;
  };
  PRINCIPALS?: Array<{
    name?: string;
    email?: string;
    [key: string]: unknown;
  }>;
  CURRENCIES?: TomlCurrency[];
  DOCUMENTATION?: {
    ORG_NAME?: string;
    ORG_DBA?: string;
    ORG_URL?: string;
    ORG_LOGO?: string;
    ORG_DESCRIPTION?: string;
    ORG_PHYSICAL_ADDRESS?: string;
    ORG_PHONE_NUMBER?: string;
    ORG_KEYBASE?: string;
    ORG_TWITTER?: string;
    ORG_GITHUB?: string;
    ORG_OFFICIAL_EMAIL?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}
