import { Injectable, Logger } from '@nestjs/common';
import { HorizonService } from '../stellar/horizon.service';
import {
  VERIFIED_STELLAR_ASSETS,
  VerifiedAssetRecord,
} from '../stellar/verified-assets.constant';
import { AssetMetadataCache } from './cache/asset-metadata.cache';
import { TomlFetcherService } from './toml-fetcher.service';
import {
  AssetBranding,
} from './types/asset-metadata.types';
import {
  AssetMetadataResponseDto,
  AssetListResponseDto,
} from './dto/asset-metadata.dto';
import { SupabaseService, VerifiedAssetDbRecord } from '../supabase/supabase.service';

@Injectable()
export class AssetMetadataService {
  private readonly logger = new Logger(AssetMetadataService.name);

  // Fallback branding for native XLM
  private readonly XLM_FALLBACK_BRANDING: AssetBranding = {
    name: 'Stellar Lumens',
    description: 'The native currency of the Stellar network',
    icon: 'https://assets.stellar.org/images/logos/xlm-icon.svg',
    logo: 'https://assets.stellar.org/images/logos/xlm-logo.svg',
  };

  // Generic fallback for unknown assets
  private readonly GENERIC_FALLBACK_BRANDING: AssetBranding = {
    name: undefined,
    description: undefined,
    icon: undefined,
    logo: undefined,
  };

  // Known issuer domains mapping (can be extended)
  private readonly KNOWN_ISSUER_DOMAINS: Record<string, string> = {
    GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN: 'circle.com',
    GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA: 'aqua.network',
    GARDNV3Q7YGT4AKSDF25LT32YSCCW4EV22Y2TV3I2PU2MMXJTEDL5T55: 'ultrastellar.com',
  };

  constructor(
    private readonly cache: AssetMetadataCache,
    private readonly tomlFetcher: TomlFetcherService,
    private readonly horizonService: HorizonService,
    private readonly supabaseService: SupabaseService,
  ) {}

  private mapDbRecordToRecord(dbRecord: VerifiedAssetDbRecord): VerifiedAssetRecord {
    return {
      code: dbRecord.code,
      type: dbRecord.type,
      issuer: dbRecord.issuer,
      verified: dbRecord.verified as true,
      decimals: dbRecord.decimals,
      branding: dbRecord.icon_url ? {
        name: dbRecord.code,
        icon: dbRecord.icon_url,
        logo: dbRecord.icon_url,
      } : undefined,
    };
  }

  /**
   * Get metadata for all verified assets, optionally filtered by a search query
   */
  async getAllAssetsMetadata(search?: string): Promise<AssetListResponseDto> {
    const cacheKey = search ? `list:search:${search.toUpperCase()}` : 'list:all';
    
    // Check cache first
    const cachedList = this.cache.get(cacheKey) as AssetListResponseDto | undefined;
    if (cachedList) {
      return cachedList;
    }

    let records: VerifiedAssetRecord[] = [];

    try {
      let dbRecords: VerifiedAssetDbRecord[] = [];
      if (search) {
        dbRecords = await this.supabaseService.searchVerifiedAssets(search);
      } else {
        dbRecords = await this.supabaseService.fetchVerifiedAssets();
      }

      // Filter only verified assets and map them
      records = dbRecords
        .filter((r) => r.verified)
        .map((r) => this.mapDbRecordToRecord(r));
    } catch (error) {
      this.logger.warn(`Failed to fetch assets from database: ${error.message}`);
    }

    // If DB returned nothing or failed, use fallback constant
    if (records.length === 0) {
      const fallbackList = VERIFIED_STELLAR_ASSETS.map(asset => ({ ...asset }));
      if (search) {
        const upperSearch = search.toUpperCase();
        records = fallbackList.filter(
          (a) =>
            a.code.toUpperCase().includes(upperSearch) ||
            (a.issuer && a.issuer.toUpperCase().includes(upperSearch)),
        ) as VerifiedAssetRecord[];
      } else {
        records = fallbackList as VerifiedAssetRecord[];
      }
    }

    const assets = await Promise.all(
      records.map((asset) => this.getAssetMetadata(asset.code, asset.issuer)),
    );

    const response: AssetListResponseDto = {
      assets,
      total: assets.length,
    };

    // Cache the list response
    this.cache.set(cacheKey, response);

    return response;
  }

  /**
   * Get metadata for a specific asset code and optional issuer
   */
  async getAssetMetadata(code: string, issuer?: string | null): Promise<AssetMetadataResponseDto> {
    const upperCode = code.toUpperCase();
    const normIssuer = issuer || null;
    const cacheKey = normIssuer ? `${upperCode}:${normIssuer.toUpperCase()}` : upperCode;

    // Check cache first
    const cached = this.cache.get(cacheKey) as {
      asset: VerifiedAssetRecord;
      branding: AssetBranding;
      isFallback: boolean;
      fetchedAt: Date;
    } | undefined;
    if (cached) {
      return this.mapToResponseDto(cached.asset, cached.branding, cached.isFallback);
    }

    // Try finding the asset:
    let verifiedAsset: VerifiedAssetRecord | undefined;

    // 1. Try DB first
    try {
      const dbRecords = await this.supabaseService.fetchVerifiedAssets();
      const dbRecord = dbRecords.find(
        (r) =>
          r.code.toUpperCase() === upperCode &&
          (normIssuer === null
            ? r.issuer === null
            : r.issuer?.toUpperCase() === normIssuer.toUpperCase())
      );
      if (dbRecord) {
        verifiedAsset = this.mapDbRecordToRecord(dbRecord);
      }
    } catch (error) {
      this.logger.debug(`Could not check DB for asset metadata: ${error.message}`);
    }

    // 2. Fall back to constant whitelist
    if (!verifiedAsset) {
      const fallback = VERIFIED_STELLAR_ASSETS.find(
        (a) =>
          a.code.toUpperCase() === upperCode &&
          (normIssuer === null
            ? a.issuer === null
            : a.issuer?.toUpperCase() === normIssuer.toUpperCase())
      );
      if (fallback) {
        verifiedAsset = { ...fallback } as VerifiedAssetRecord;
      }
    }

    if (!verifiedAsset) {
      // Return unverified asset with fallback branding
      return this.createUnverifiedResponse(code);
    }

    // Fetch branding from TOML or use fallback
    const branding = await this.fetchAssetBranding(verifiedAsset);
    const isFallback = this.isFallbackBranding(branding, verifiedAsset);

    // Cache the result
    const cachedMetadata = {
      asset: verifiedAsset,
      branding,
      isFallback,
      fetchedAt: new Date(),
    };
    this.cache.set(cacheKey, cachedMetadata);

    return this.mapToResponseDto(verifiedAsset, branding, isFallback);
  }

  /**
   * Refresh metadata for a specific asset (clear cache and re-fetch)
   */
  async refreshAssetMetadata(code: string, issuer?: string | null): Promise<AssetMetadataResponseDto> {
    const normIssuer = issuer || null;
    const cacheKey = normIssuer ? `${code.toUpperCase()}:${normIssuer.toUpperCase()}` : code.toUpperCase();
    this.cache.delete(cacheKey);
    // Clear list cache to reflect any changes
    this.cache.clear();
    return this.getAssetMetadata(code, issuer);
  }

  /**
   * Mark an asset as verified/unverified in database and clear cache
   */
  async verifyAsset(
    code: string,
    issuer: string | null,
    verified: boolean,
    additionalData?: {
      type?: 'native' | 'credit_alphanum4' | 'credit_alphanum12';
      decimals?: number;
      iconUrl?: string | null;
    }
  ): Promise<AssetMetadataResponseDto> {
    const normCode = code.toUpperCase();
    const normIssuer = issuer || null;

    // Save/update in database
    await this.supabaseService.upsertVerifiedAsset({
      code: normCode,
      issuer: normIssuer,
      type: additionalData?.type || (normCode === 'XLM' ? 'native' : 'credit_alphanum4'),
      decimals: additionalData?.decimals ?? 7,
      icon_url: additionalData?.iconUrl || null,
      verified,
    });

    // Clear entire cache immediately so changes are reflected
    this.cache.clear();

    // Fetch fresh metadata
    return this.getAssetMetadata(normCode, normIssuer);
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; maxSize: number; ttl: number } {
    return this.cache.getStats();
  }

  /**
   * Clear all cached metadata
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Fetch asset branding from TOML or use fallback
   */
  private async fetchAssetBranding(
    asset: VerifiedAssetRecord,
  ): Promise<AssetBranding> {
    // XLM is native, handle specially
    if (asset.code === 'XLM' && asset.type === 'native') {
      return this.XLM_FALLBACK_BRANDING;
    }

    // If no issuer, use generic fallback
    if (!asset.issuer) {
      return this.GENERIC_FALLBACK_BRANDING;
    }

    // Try to fetch TOML from issuer's domain
    try {
      // First, try to get domain from Horizon (if account has home_domain set)
      const domainFromHorizon = await this.getDomainFromHorizon(asset.issuer);
      
      // If no domain in Horizon, check our known domains mapping
      const domain = domainFromHorizon || this.KNOWN_ISSUER_DOMAINS[asset.issuer];

      if (domain) {
        const toml = await this.tomlFetcher.fetchStellarToml(domain);
        if (toml) {
          const currency = this.tomlFetcher.findCurrency(toml, asset.code);
          if (currency) {
            this.logger.log(
              `Found TOML branding for ${asset.code} from ${domain}`,
            );
            return this.tomlFetcher.extractBranding(currency, toml);
          }
        }
      }
    } catch (error) {
      this.logger.warn(
        `Failed to fetch TOML for ${asset.code}: ${error.message}`,
      );
    }

    // Return generic fallback if TOML fetch failed
    return {
      ...this.GENERIC_FALLBACK_BRANDING,
      name: asset.code,
    };
  }

  /**
   * Get domain from Horizon account information
   */
  private async getDomainFromHorizon(issuer: string): Promise<string | null> {
    try {
      const account = await this.horizonService.getAccount(issuer);
      return account?.home_domain || null;
    } catch (error) {
      this.logger.debug(`Could not fetch account ${issuer} from Horizon`);
      return null;
    }
  }

  /**
   * Check if branding is a fallback
   */
  private isFallbackBranding(
    branding: AssetBranding,
    asset: VerifiedAssetRecord,
  ): boolean {
    // XLM is not considered fallback
    if (asset.code === 'XLM' && asset.type === 'native') {
      return false;
    }

    // If no icon/logo, it's a fallback
    return !branding.icon && !branding.logo;
  }

  /**
   * Create response for unverified asset
   */
  private createUnverifiedResponse(code: string): AssetMetadataResponseDto {
    return {
      code,
      type: 'credit_alphanum4',
      issuer: undefined,
      verified: false,
      decimals: 7,
      branding: {
        name: code,
        icon: undefined,
        logo: undefined,
        description: undefined,
      },
      isFallback: true,
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * Map to response DTO
   */
  private mapToResponseDto(
    asset: VerifiedAssetRecord,
    branding: AssetBranding,
    isFallback: boolean,
  ): AssetMetadataResponseDto {
    return {
      code: asset.code,
      type: asset.type,
      issuer: asset.issuer || undefined,
      verified: asset.verified,
      decimals: asset.decimals,
      branding: {
        name: branding.name,
        icon: branding.icon,
        logo: branding.logo,
        description: branding.description,
        conditions: branding.conditions,
        isAssetAnchored: branding.is_asset_anchored,
        anchorAssetType: branding.anchor_asset_type,
        anchorAsset: branding.anchor_asset,
        attestationOfReserve: branding.attestation_of_reserve,
        redemptionInstructions: branding.redemption_instructions,
      },
      isFallback,
      updatedAt: new Date().toISOString(),
    };
  }
}
