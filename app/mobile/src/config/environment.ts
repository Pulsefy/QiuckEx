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

export interface BackendMetadata {
  appVersion: string;
  minAppVersion: string;
  environment: string;
  stellarNetwork: string;
}

export interface CompatibilityResult {
  compatible: boolean;
  reason?: string;
}
