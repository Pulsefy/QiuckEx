import * as StellarSdk from '@stellar/stellar-sdk';

export type StellarNetwork = 'testnet' | 'mainnet';

export type NetworkSnapshot = {
  network: StellarNetwork;
  passphrase: string;
  horizonUrl: string;
  sorobanRpcUrl: string;
  sorobanRpcUrls: string[];
  explorerUrl: string;
};

const NETWORK_ALIASES = ['NETWORK', 'STELLAR_NETWORK'] as const;

const DEFAULT_NETWORK: StellarNetwork = 'testnet';

const DEFAULT_ENDPOINTS: Record<
  StellarNetwork,
  Omit<NetworkSnapshot, 'network'>
> = {
  testnet: {
    passphrase: StellarSdk.Networks.TESTNET,
    horizonUrl: 'https://horizon-testnet.stellar.org',
    sorobanRpcUrl: 'https://soroban-testnet.stellar.org',
    sorobanRpcUrls: ['https://soroban-testnet.stellar.org'],
    explorerUrl: 'https://stellar.expert/explorer/testnet',
  },
  mainnet: {
    passphrase: StellarSdk.Networks.PUBLIC,
    horizonUrl: 'https://horizon.stellar.org',
    sorobanRpcUrl: 'https://soroban-rpc.mainnet.stellar.gateway.fm',
    sorobanRpcUrls: ['https://soroban-rpc.mainnet.stellar.gateway.fm'],
    explorerUrl: 'https://stellar.expert/explorer/public',
  },
};

function normalizeNetworkValue(value?: string): StellarNetwork | undefined {
  if (!value) return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'testnet' || normalized === 'mainnet') return normalized;
  throw new Error(
    `Invalid network value "${value}". Use "testnet" or "mainnet".`,
  );
}

function isValidHttpUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export function resolveNetworkSnapshot(
  env: Record<string, string | undefined> = process.env,
): NetworkSnapshot {
  const aliasValues = NETWORK_ALIASES.map((key) => ({
    key,
    value: normalizeNetworkValue(env[key]),
  })).filter((entry) => entry.value !== undefined);

  const unique = new Set(aliasValues.map((entry) => entry.value));
  if (unique.size > 1) {
    throw new Error(
      'NETWORK and STELLAR_NETWORK are both set but conflict. Use a single network value.',
    );
  }

  const network = aliasValues[0]?.value ?? DEFAULT_NETWORK;
  const defaults = DEFAULT_ENDPOINTS[network];

  const horizonUrl = env.HORIZON_URL?.trim() || defaults.horizonUrl;
  const sorobanRpcUrl = env.SOROBAN_RPC_URL?.trim() || defaults.sorobanRpcUrl;
  const sorobanRpcUrls = [
    sorobanRpcUrl,
    ...(env.SOROBAN_RPC_URLS ?? '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean),
  ];
  const explorerUrl = env.STELLAR_EXPLORER_URL?.trim() || defaults.explorerUrl;

  if (!isValidHttpUrl(horizonUrl)) {
    throw new Error(`Invalid HORIZON_URL "${horizonUrl}". Expected http/https URL.`);
  }
  if (!isValidHttpUrl(sorobanRpcUrl)) {
    throw new Error(
      `Invalid SOROBAN_RPC_URL "${sorobanRpcUrl}". Expected http/https URL.`,
    );
  }
  if (!isValidHttpUrl(explorerUrl)) {
    throw new Error(
      `Invalid STELLAR_EXPLORER_URL "${explorerUrl}". Expected http/https URL.`,
    );
  }

  return {
    network,
    passphrase: defaults.passphrase,
    horizonUrl,
    sorobanRpcUrl,
    sorobanRpcUrls: Array.from(new Set(sorobanRpcUrls)),
    explorerUrl,
  };
}
