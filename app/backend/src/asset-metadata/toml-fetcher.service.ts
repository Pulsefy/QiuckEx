import { Injectable, Logger } from '@nestjs/common';
import * as toml from 'toml';
import {
  ParsedStellarToml,
  TomlCurrency,
  AssetBranding,
} from './types/asset-metadata.types';

@Injectable()
export class TomlFetcherService {
  private readonly logger = new Logger(TomlFetcherService.name);
  private readonly TIMEOUT_MS = 5000; // 5 second timeout

  /**
   * Fetch and parse stellar.toml from an issuer's domain
   * @param domain - The domain to fetch TOML from
   * @returns Parsed TOML or null if failed
   */
  async fetchStellarToml(domain: string): Promise<ParsedStellarToml | null> {
    if (!domain) {
      this.logger.warn('No domain provided for TOML fetch');
      return null;
    }

    // Normalize domain
    const normalizedDomain = domain.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const urls = [
      `https://${normalizedDomain}/.well-known/stellar.toml`,
      `https://${normalizedDomain}/stellar.toml`,
    ];

    for (const url of urls) {
      try {
        this.logger.debug(`Fetching TOML from: ${url}`);
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.TIMEOUT_MS);

        const response = await fetch(url, {
          signal: controller.signal,
          headers: {
            Accept: 'text/plain, application/toml',
          },
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          this.logger.debug(`TOML fetch failed for ${url}: ${response.status}`);
          continue;
        }

        const tomlText = await response.text();
        const parsed = this.parseToml(tomlText);

        if (parsed) {
          this.logger.debug(`Successfully parsed TOML from ${url}`);
          return parsed;
        }
      } catch (error) {
        this.logger.debug(`Error fetching TOML from ${url}: ${error.message}`);
        continue;
      }
    }

    this.logger.warn(`Failed to fetch TOML from any URL for domain: ${domain}`);
    return null;
  }

  /**
   * Extract currency information for a specific asset code
   * @param toml - Parsed TOML
   * @param assetCode - Asset code to find
   * @returns Currency info or null if not found
   */
  findCurrency(
    toml: ParsedStellarToml,
    assetCode: string,
  ): TomlCurrency | null {
    if (!toml.CURRENCIES || !Array.isArray(toml.CURRENCIES)) {
      return null;
    }

    const upperCode = assetCode.toUpperCase();
    const currency = toml.CURRENCIES.find(
      (c) => c.code?.toUpperCase() === upperCode,
    );

    return currency || null;
  }

  /**
   * Convert TOML currency to asset branding
   * @param currency - TOML currency entry
   * @param toml - Full parsed TOML for context
   * @returns Asset branding information
   */
  extractBranding(currency: TomlCurrency, toml: ParsedStellarToml): AssetBranding {
    const branding: AssetBranding = {
      name: currency.name,
      description: currency.desc,
      conditions: currency.conditions,
      is_asset_anchored: currency.is_asset_anchored,
      anchor_asset_type: currency.anchor_asset_type,
      anchor_asset: currency.anchor_asset,
      attestation_of_reserve: currency.attestation_of_reserve,
      redemption_instructions: currency.redemption_instructions,
      collateral_addresses: currency.collateral_addresses,
      collateral_address_signatures: currency.collateral_address_signatures,
    };

    // Handle image/logo - can be a direct URL or relative path
    if (currency.image) {
      branding.icon = this.resolveUrl(currency.image, toml);
      branding.logo = branding.icon;
    }

    // If no currency image, try organization logo from DOCUMENTATION
    if (!branding.logo && toml.DOCUMENTATION?.ORG_LOGO) {
      branding.logo = this.resolveUrl(toml.DOCUMENTATION.ORG_LOGO, toml);
    }

    return branding;
  }

  /**
   * Parse TOML text into structured object
   */
  private parseToml(tomlText: string): ParsedStellarToml | null {
    try {
      // Use @iarna/toml parser which handles Stellar TOML format well
      const parsed = toml.parse(tomlText) as ParsedStellarToml;
      return parsed;
    } catch (error) {
      this.logger.error(`Failed to parse TOML: ${error.message}`);
      return null;
    }
  }

  /**
   * Resolve a potentially relative URL to absolute
   */
  private resolveUrl(url: string, toml: ParsedStellarToml): string {
    if (!url) return url;
    
    // Already absolute URL
    if (url.startsWith('http://') || url.startsWith('https://')) {
      return url;
    }

    // Try to construct from ORG_URL in DOCUMENTATION
    const orgUrl = toml.DOCUMENTATION?.ORG_URL;
    if (orgUrl) {
      const base = orgUrl.replace(/\/$/, '');
      const path = url.startsWith('/') ? url : `/${url}`;
      return `${base}${path}`;
    }

    // Return as-is if we can't resolve
    return url;
  }
}
