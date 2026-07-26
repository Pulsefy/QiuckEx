export type EnvironmentId = 'production' | 'staging' | 'testnet' | 'branch-preview';

export interface EnvironmentConfig {
  id: EnvironmentId;
  label: string;
  apiUrl: string;
  stellarNetwork: 'mainnet' | 'testnet';
  buildTag?: string;
}

export const ENVIRONMENTS: Record<EnvironmentId, EnvironmentConfig> = {
  production: {
    id: 'production',
    label: 'Production',
    apiUrl: 'https://api.quickex.to',
    stellarNetwork: 'mainnet',
  },
  staging: {
    id: 'staging',
    label: 'Staging',
    apiUrl: 'https://staging-api.quickex.to',
    stellarNetwork: 'testnet',
    buildTag: 'staging',
  },
  testnet: {
    id: 'testnet',
    label: 'Shared Testnet',
    apiUrl: 'https://testnet-api.quickex.to',
    stellarNetwork: 'testnet',
    buildTag: 'testnet',
  },
  'branch-preview': {
    id: 'branch-preview',
    label: 'Branch Preview',
    apiUrl: 'https://preview-api.quickex.to',
    stellarNetwork: 'testnet',
    buildTag: 'preview',
  },
};

export const DEFAULT_ENVIRONMENT: EnvironmentId = 'production';

export interface RuntimeContractConfig {
  id: string;
  version: string;
}

export type RuntimeContracts = Record<string, RuntimeContractConfig>;

export interface RuntimePreviewConfig {
  branch?: string;
  previewUrl?: string;
  expiresAt?: string;
}

export interface BackendMetadata {
  appVersion: string;
  minAppVersion: string;
  environment: string;
  stellarNetwork: string;
  contracts?: RuntimeContracts;
  preview?: RuntimePreviewConfig;
}

export interface CompatibilityResult {
  compatible: boolean;
  reason?: string;
}

/**
 * Fills in safe defaults for a bootstrap payload that omits fields —
 * preview/testnet backends may not populate every field yet.
 */
export function normalizeBackendMetadata(
  data: Partial<BackendMetadata> | null | undefined,
  fallback: EnvironmentConfig,
): BackendMetadata {
  return {
    appVersion: data?.appVersion ?? 'unknown',
    minAppVersion: data?.minAppVersion ?? '0.0.0',
    environment: data?.environment ?? fallback.id,
    stellarNetwork: data?.stellarNetwork ?? fallback.stellarNetwork,
    contracts: data?.contracts ?? {},
    preview: data?.preview,
  };
}
