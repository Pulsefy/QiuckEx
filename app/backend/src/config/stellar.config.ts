import { registerAs } from '@nestjs/config';

export type Network = 'testnet' | 'mainnet';

export type AssetType = 'native' | 'credit_alphanum4' | 'credit_alphanum12';

export type NativeAsset = {
  type: 'native';
  code: 'XLM';
};

export type IssuedAsset = {
  type: 'credit_alphanum4' | 'credit_alphanum12';
  code: string;
  issuer: string;
};

export type SupportedAsset = NativeAsset | IssuedAsset;

export type AssetInput = {
  code: string;
  issuer?: string | null;
  type?: AssetType | null;
};

export type NormalizedAsset = {
  type: AssetType;
  code: string;
  issuer?: string;
};

export const NETWORK_ENV_KEY = 'STELLAR_NETWORK';
export const DEFAULT_NETWORK: Network = 'testnet';

export const USDC_ISSUER =
  'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2K34P4D5NXJ6Z4GJ5B7G';

export const SUPPORTED_ASSETS = [
  {
    type: 'native',
    code: 'XLM',
  },
  {
    type: 'credit_alphanum4',
    code: 'USDC',
    issuer: USDC_ISSUER,
  },
] as const satisfies readonly SupportedAsset[];

export const HORIZON_BASE_URLS: Record<Network, string> = {
  testnet: 'https://horizon-testnet.stellar.org',
  mainnet: 'https://horizon.stellar.org',
};

export class InvalidNetworkError extends Error {
  readonly value: string;

  constructor(value: string) {
    super(
      `Invalid ${NETWORK_ENV_KEY} value "${value}". Use "testnet" or "mainnet".`,
    );
    this.name = 'InvalidNetworkError';
    this.value = value;
  }
}

export class UnsupportedAssetError extends Error {
  readonly asset: NormalizedAsset;

  constructor(asset: NormalizedAsset) {
    const issuerSuffix = asset.issuer ? `:${asset.issuer}` : '';
    super(`Unsupported asset "${asset.code}${issuerSuffix}".`);
    this.name = 'UnsupportedAssetError';
    this.asset = asset;
  }
}

export function normalizeAssetCode(code: string): string {
  return code.trim().toUpperCase();
}

export function normalizeAsset(input: AssetInput): NormalizedAsset {
  const code = normalizeAssetCode(
    typeof input.code === 'string' ? input.code : '',
  );
  const isNative = code === 'XLM' || input.type === 'native';
  const type: AssetType = isNative
    ? 'native'
    : code.length <= 4
      ? 'credit_alphanum4'
      : 'credit_alphanum12';
  const issuer =
    type === 'native' || typeof input.issuer !== 'string'
      ? undefined
      : input.issuer;

  return {
    type,
    code,
    issuer,
  };
}

export function isSupportedAsset(input: AssetInput): boolean {
  const normalized = normalizeAsset(input);

  if (!normalized.code) {
    return false;
  }

  if (normalized.type !== 'native' && !normalized.issuer) {
    return false;
  }

  return SUPPORTED_ASSETS.some((asset) => {
    if (asset.type === 'native') {
      return normalized.type === 'native' && asset.code === normalized.code;
    }

    return (
      normalized.type !== 'native' &&
      asset.type === normalized.type &&
      asset.code === normalized.code &&
      asset.issuer === normalized.issuer
    );
  });
}

export function assertSupportedAsset(input: AssetInput): NormalizedAsset {
  const normalized = normalizeAsset(input);

  if (!isSupportedAsset(normalized)) {
    throw new UnsupportedAssetError(normalized);
  }

  return normalized;
}

export function resolveNetwork(
  value: string | undefined = process.env[NETWORK_ENV_KEY],
): Network {
  if (!value) {
    return DEFAULT_NETWORK;
  }

  const normalized = value.trim().toLowerCase();

  if (normalized === 'testnet' || normalized === 'mainnet') {
    return normalized;
  }

  throw new InvalidNetworkError(value);
}

export let NETWORK: Network = DEFAULT_NETWORK;
export let HORIZON_BASE_URL = HORIZON_BASE_URLS[DEFAULT_NETWORK];

export function syncNetworkFromEnv(
  value: string | undefined = process.env[NETWORK_ENV_KEY],
): Network {
  const network = resolveNetwork(value);
  NETWORK = network;
  HORIZON_BASE_URL = HORIZON_BASE_URLS[network];
  return network;
}

export const stellarConfig = registerAs('stellar', () => {
  const network = syncNetworkFromEnv();

  return {
    network,
    horizonBaseUrl: HORIZON_BASE_URLS[network],
    supportedAssets: SUPPORTED_ASSETS,
  };
});
