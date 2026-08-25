import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash } from 'crypto';

import { AppConfigService } from '../config';
import { ContractRegistryService } from '../contracts/contract-registry.service';
import { FeatureFlagsService } from '../feature-flags/feature-flags.service';
import { PreviewScopeService } from '../preview-scope/preview-scope.service';
import {
  RuntimeConfigResponseDto,
  NetworkConfigDto,
  ContractEntryDto,
  FeatureFlagEntryDto,
  PreviewMetadataDto,
  MobileVersionPolicyDto,
} from './dto/runtime-config.dto';

@Injectable()
export class RuntimeConfigService {
  private readonly logger = new Logger(RuntimeConfigService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly appConfigService: AppConfigService,
    private readonly featureFlagsService: FeatureFlagsService,
    private readonly contractRegistryService: ContractRegistryService,
    private readonly previewScopeService: PreviewScopeService,
  ) {}

  async getConfig(previewScope?: string): Promise<RuntimeConfigResponseDto> {
    const environment = this.resolveEnvironmentName();

    const [network, contracts, featureFlagsResponse, preview] = await Promise.all([
      this.buildNetworkConfig(),
      this.buildContractsConfig(),
      this.loadFeatureFlags(environment),
      previewScope ? this.buildPreviewMetadata(previewScope) : Promise.resolve(undefined),
    ]);

    const featureFlags: FeatureFlagEntryDto[] = featureFlagsResponse.flags.map((flag) => ({
      key: flag.key,
      name: flag.name,
      enabled: flag.enabled,
      killSwitch: flag.killSwitch,
      rolloutPercentage: flag.rolloutPercentage,
    }));

    const contractsConfig = contracts ?? {};

    const mobileVersionPolicy = this.buildMobileVersionPolicy();

    const etag = this.buildEtag(network, contractsConfig, featureFlags, preview, mobileVersionPolicy);

    return {
      environment,
      network,
      apiUrl: this.resolveApiUrl(),
      appVersion: '0.1.0',
      minAppVersion: mobileVersionPolicy.minSupportedVersion,
      mobileVersionPolicy,
      contracts: contractsConfig,
      featureFlags,
      preview,
      generatedAt: new Date().toISOString(),
      etag,
    };
  }

  private async buildNetworkConfig(): Promise<NetworkConfigDto> {
    const stellar = this.configService.get<{
      network: 'testnet' | 'mainnet';
      networkPassphrase: string;
      horizonBaseUrl: string;
      sorobanRpcUrl: string;
      sorobanRpcUrls: string[];
      explorerUrl: string;
    }>('stellar');

    return {
      network: stellar?.network ?? 'testnet',
      networkPassphrase: stellar?.networkPassphrase ?? 'Test SDF Network ; September 2015',
      horizonUrl: stellar?.horizonBaseUrl ?? 'https://horizon-testnet.stellar.org',
      sorobanRpcUrl: stellar?.sorobanRpcUrl ?? 'https://soroban-testnet.stellar.org',
      sorobanRpcUrls: stellar?.sorobanRpcUrls ?? ['https://soroban-testnet.stellar.org'],
      explorerUrl: stellar?.explorerUrl ?? 'https://stellar.expert/explorer/testnet',
    };
  }

  private async buildContractsConfig(): Promise<Record<string, ContractEntryDto>> {
    try {
      const registry = await this.contractRegistryService.getRegistry();
      const entries: Record<string, ContractEntryDto> = {};
      for (const [name, data] of Object.entries(registry.data)) {
        const typed = data as Record<string, unknown>;
        entries[name] = {
          contractId: String(typed.id ?? ''),
          wasmHash: String(typed.wasmHash ?? ''),
          version: Number(typed.version ?? 0),
          schemaVersion: String(typed.schemaVersion ?? '1.0.0'),
        };
      }
      return entries;
    } catch (error) {
      this.logger.warn(`Contract registry unavailable, returning empty: ${(error as Error).message}`);
      return {};
    }
  }

  private async loadFeatureFlags(environment: string) {
    try {
      return await this.featureFlagsService.getSnapshot(environment);
    } catch (error) {
      this.logger.warn(`Feature flags unavailable, returning empty: ${(error as Error).message}`);
      return { flags: [], metadata: { source: 'bootstrap' as const, storeAvailable: false, flagCount: 0, sensitiveFlagCount: 0, timestamp: new Date().toISOString() } };
    }
  }

  private async buildPreviewMetadata(scopeId: string): Promise<PreviewMetadataDto | undefined> {
    try {
      const scope = await this.previewScopeService.getScope(scopeId);
      if (!scope) return undefined;

      const now = new Date();
      const expiresAt = new Date(scope.expires_at);
      return {
        scopeId: scope.scope_id,
        branchName: scope.branch_name,
        expiresAt: scope.expires_at,
        valid: expiresAt > now,
      };
    } catch (error) {
      this.logger.warn(`Preview scope lookup failed for ${scopeId}: ${(error as Error).message}`);
      return undefined;
    }
  }

  private resolveEnvironmentName(): string {
    return this.appConfigService.environmentName ?? this.appConfigService.nodeEnv;
  }

  private resolveApiUrl(): string {
    const configured = this.appConfigService.publicApiUrl;
    if (configured) return configured;

    if (this.appConfigService.isMainnet) return 'https://api.quickex.to';
    if (this.appConfigService.isStaging) return 'https://staging-api.quickex.to';
    return 'https://testnet-api.quickex.to';
  }

  private buildMobileVersionPolicy(): MobileVersionPolicyDto {
    return {
      minSupportedVersion: this.appConfigService.mobileMinSupportedVersion,
      recommendedVersion: this.appConfigService.mobileRecommendedVersion,
      latestVersion: this.appConfigService.mobileLatestVersion,
      iosStoreUrl: this.appConfigService.mobileIosStoreUrl,
      androidStoreUrl: this.appConfigService.mobileAndroidStoreUrl,
      releaseNotes: this.appConfigService.mobileReleaseNotes,
    };
  }

  private buildEtag(
    network: NetworkConfigDto,
    contracts: Record<string, ContractEntryDto>,
    flags: FeatureFlagEntryDto[],
    preview: PreviewMetadataDto | undefined,
    mobileVersionPolicy: MobileVersionPolicyDto,
  ): string {
    const stable = JSON.stringify({
      n: network.network,
      c: Object.keys(contracts).sort().map((k) => `${k}:${contracts[k].contractId}`).join(','),
      f: flags.map((f) => `${f.key}:${f.enabled}`).sort().join(','),
      p: preview?.scopeId,
      v: `${mobileVersionPolicy.minSupportedVersion}:${mobileVersionPolicy.recommendedVersion}:${mobileVersionPolicy.latestVersion}`,
    });
    const hash = createHash('sha256').update(stable).digest('hex').slice(0, 16);
    return `W/"runtime-config-${hash}"`;
  }

  validateConfig(config: RuntimeConfigResponseDto): void {
    if (!config.network.network) {
      this.logger.warn('Runtime config missing network - using testnet default');
    }
    if (!config.apiUrl) {
      this.logger.warn('Runtime config missing apiUrl - clients may be unable to reach API');
    }
  }
}
