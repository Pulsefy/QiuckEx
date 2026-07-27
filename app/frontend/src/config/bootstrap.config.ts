export interface BootstrapConfig {
  network: {
    environment: string;
    rpcUrl: string;
    horizonUrl: string;
    networkPassphrase: string;
  };
  contracts: {
    registryId: string;
    routerId: string;
    allowedTokens: string[];
  };
  backendMetadata: {
    version: string;
    apiUrl: string;
    featureFlags: Record<string, boolean>;
  };
}

export const FALLBACK_BOOTSTRAP_CONFIG: BootstrapConfig = {
  network: {
    environment: 'testnet',
    rpcUrl: 'https://soroban-testnet.stellar.org',
    horizonUrl: 'https://horizon-testnet.stellar.org',
    networkPassphrase: 'Test SDF Network ; September 2015',
  },
  contracts: {
    registryId: '',
    routerId: '',
    allowedTokens: [],
  },
  backendMetadata: {
    version: 'fallback',
    apiUrl: process.env.VITE_API_BASE_URL || 'http://localhost:4000',
    featureFlags: {
      contractWriteKillSwitch: false,
      enableShadowTraffic: false,
    },
  },
};