import type { EnvironmentId } from '../src/config/environment';

export interface NetworkConfig {
  network: 'public' | 'testnet' | 'standalone' | string;
  horizonUrl: string;
  sorobanRpcUrl: string;
  networkPassphrase: string;
}

export interface ContractEntry {
  contractId: string;
  address: string;
  deployedAt?: string;
  version?: string;
}

export interface FeatureFlagEntry {
  [key: string]: boolean | string | number | unknown;
}

export interface PreviewMetadata {
  scope: string;
  branch: string;
  commitSha?: string;
  deployedAt?: string;
  expiresAt?: string;
}

export interface MobileVersionPolicy {
  minAppVersion: string;
  latestAppVersion: string;
  forceUpdate: boolean;
  updateUrl?: string;
  message?: string;
}

export interface RuntimeConfig {
  environment: EnvironmentId;
  apiUrl: string;
  appVersion: string;
  minAppVersion: string;
  network: NetworkConfig;
  contracts: ContractEntry[];
  featureFlags: FeatureFlagEntry;
  preview: PreviewMetadata | null;
  mobileVersionPolicy: MobileVersionPolicy;
  etag?: string;
  fetchedAt?: number;
}

export interface PartialRuntimeConfigResponse {
  environment?: string;
  apiUrl?: string;
  appVersion?: string;
  minAppVersion?: string;
  network?: Partial<NetworkConfig>;
  contracts?: Partial<ContractEntry>[];
  featureFlags?: FeatureFlagEntry;
  preview?: Partial<PreviewMetadata> | null;
  mobileVersionPolicy?: Partial<MobileVersionPolicy>;
  etag?: string;
}
