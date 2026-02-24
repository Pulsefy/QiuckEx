import {
  DEFAULT_NETWORK,
  HORIZON_BASE_URL,
  HORIZON_BASE_URLS,
  InvalidNetworkError,
  NETWORK_ENV_KEY,
  NETWORK,
  SUPPORTED_ASSETS,
  USDC_ISSUER,
  assertSupportedAsset,
  isSupportedAsset,
  resolveNetwork,
  syncNetworkFromEnv,
  stellarConfig,
  UnsupportedAssetError,
} from './stellar.config';

describe('stellar config', () => {
  const originalNetwork = process.env[NETWORK_ENV_KEY];

  afterEach(() => {
    if (originalNetwork === undefined) {
      delete process.env[NETWORK_ENV_KEY];
    } else {
      process.env[NETWORK_ENV_KEY] = originalNetwork;
    }
    syncNetworkFromEnv(originalNetwork);
  });

  describe('asset validation', () => {
    it('accepts native XLM', () => {
      expect(isSupportedAsset({ code: 'XLM' })).toBe(true);
      expect(isSupportedAsset({ code: 'xlm', issuer: 'GABC' })).toBe(true);
    });

    it('accepts issued USDC with matching issuer', () => {
      expect(isSupportedAsset({ code: 'USDC', issuer: USDC_ISSUER })).toBe(
        true,
      );
    });

    it('rejects issued assets with mismatched issuer', () => {
      expect(
        isSupportedAsset({ code: 'USDC', issuer: 'GBADISSUER' }),
      ).toBe(false);
    });

    it('rejects unknown asset codes', () => {
      expect(isSupportedAsset({ code: 'ABC', issuer: USDC_ISSUER })).toBe(
        false,
      );
    });

    it('throws a typed error for unsupported assets', () => {
      expect(() => assertSupportedAsset({ code: 'ABC' })).toThrow(
        UnsupportedAssetError,
      );
    });
  });

  describe('network resolution', () => {
    it('defaults to testnet when env is missing', () => {
      delete process.env[NETWORK_ENV_KEY];
      expect(resolveNetwork()).toBe(DEFAULT_NETWORK);
    });

    it('reads the network from env', () => {
      process.env[NETWORK_ENV_KEY] = 'mainnet';
      expect(resolveNetwork()).toBe('mainnet');
    });

    it('rejects invalid env values', () => {
      process.env[NETWORK_ENV_KEY] = 'devnet';
      expect(() => resolveNetwork()).toThrow(InvalidNetworkError);
    });
  });

  it('exposes typed config values', () => {
    process.env[NETWORK_ENV_KEY] = 'testnet';
    const config = stellarConfig();

    expect(config.network).toBe('testnet');
    expect(config.horizonBaseUrl).toBe(HORIZON_BASE_URLS.testnet);
    expect(config.supportedAssets).toBe(SUPPORTED_ASSETS);
    expect(NETWORK).toBe('testnet');
    expect(HORIZON_BASE_URL).toBe(HORIZON_BASE_URLS.testnet);
  });
});
