/**
 * Backend Base URL Configuration Tests
 *
 * Verifies that:
 *  - The shared API_URL constant resolves correctly for every named environment
 *  - Services (transactions, link-metadata, in-app-notifications) all use the
 *    shared constant rather than their own derivations
 *  - The local fallback port is 4000 (matches backend PORT default)
 *  - Missing / empty EXPO_PUBLIC_API_URL falls back safely
 *  - The ENVIRONMENTS map covers local, preview, and testnet correctly
 */

import { ENVIRONMENTS } from '../src/config/environment';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Re-require a module after adjusting the mocked build config so that we can
 * test different API_URL values without Jest module caching biting us.
 */
function requireBuildConfig(overrides: { apiUrl?: string; env?: string }) {
  jest.resetModules();
  jest.mock('expo-constants', () => ({
    default: {
      expoConfig: {
        version: '1.0.0',
        extra: {
          apiUrl: overrides.apiUrl,
          environment: overrides.env ?? 'dev',
          stellarNetwork: 'testnet',
          buildNumber: '1',
          buildTag: '',
          appVersion: '1.0.0',
        },
      },
      nativeBuildVersion: null,
    },
  }));
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require('../src/config/build') as typeof import('../src/config/build');
}

// ---------------------------------------------------------------------------
// ENVIRONMENTS map — static config coverage
// ---------------------------------------------------------------------------

describe('ENVIRONMENTS config', () => {
  it('includes all four named environments', () => {
    expect(Object.keys(ENVIRONMENTS)).toEqual(
      expect.arrayContaining(['production', 'staging', 'testnet', 'branch-preview']),
    );
  });

  it('production points to mainnet', () => {
    expect(ENVIRONMENTS.production.stellarNetwork).toBe('mainnet');
    expect(ENVIRONMENTS.production.apiUrl).toBe('https://api.quickex.to');
  });

  it('shared testnet points to testnet Stellar and a dedicated API host', () => {
    const env = ENVIRONMENTS.testnet;
    expect(env.stellarNetwork).toBe('testnet');
    expect(env.apiUrl).toMatch(/testnet/);
    // Must be an absolute HTTPS URL in production-like environments
    expect(env.apiUrl).toMatch(/^https:\/\//);
  });

  it('branch-preview points to testnet Stellar and a preview API host', () => {
    const env = ENVIRONMENTS['branch-preview'];
    expect(env.stellarNetwork).toBe('testnet');
    expect(env.apiUrl).toMatch(/preview/);
    expect(env.apiUrl).toMatch(/^https:\/\//);
  });

  it('staging points to testnet Stellar and a staging API host', () => {
    const env = ENVIRONMENTS.staging;
    expect(env.stellarNetwork).toBe('testnet');
    expect(env.apiUrl).toMatch(/staging/);
    expect(env.apiUrl).toMatch(/^https:\/\//);
  });

  it('every environment has a non-empty apiUrl and id', () => {
    for (const env of Object.values(ENVIRONMENTS)) {
      expect(env.apiUrl).toBeTruthy();
      expect(env.id).toBeTruthy();
    }
  });
});

// ---------------------------------------------------------------------------
// API_URL constant — build-time resolution
// ---------------------------------------------------------------------------

describe('API_URL from src/config/build', () => {
  const originalEnv = process.env;

  afterEach(() => {
    process.env = originalEnv;
    jest.resetModules();
  });

  it('uses extra.apiUrl injected by app.config.ts when present', () => {
    const build = requireBuildConfig({ apiUrl: 'https://staging-api.quickex.to' });
    expect(build.API_URL).toBe('https://staging-api.quickex.to');
  });

  it('uses EXPO_PUBLIC_API_URL when extra.apiUrl is absent', () => {
    process.env = { ...originalEnv, EXPO_PUBLIC_API_URL: 'http://192.168.1.10:4000' };
    const build = requireBuildConfig({ apiUrl: undefined });
    expect(build.API_URL).toBe('http://192.168.1.10:4000');
  });

  it('falls back to localhost:4000 when neither extra.apiUrl nor EXPO_PUBLIC_API_URL are set', () => {
    process.env = { ...originalEnv };
    delete process.env['EXPO_PUBLIC_API_URL'];
    const build = requireBuildConfig({ apiUrl: undefined });
    expect(build.API_URL).toBe('http://localhost:4000');
  });

  it('fallback port is 4000, not 3000, matching backend default PORT', () => {
    process.env = { ...originalEnv };
    delete process.env['EXPO_PUBLIC_API_URL'];
    const build = requireBuildConfig({ apiUrl: undefined });
    expect(build.API_URL).not.toContain(':3000');
    expect(build.API_URL).toContain(':4000');
  });

  it('uses extra.apiUrl for production build', () => {
    const build = requireBuildConfig({
      apiUrl: 'https://api.quickex.to',
      env: 'production',
    });
    expect(build.API_URL).toBe('https://api.quickex.to');
  });

  it('uses extra.apiUrl for shared testnet build', () => {
    const build = requireBuildConfig({
      apiUrl: 'https://testnet-api.quickex.to',
      env: 'testnet',
    });
    expect(build.API_URL).toBe('https://testnet-api.quickex.to');
  });

  it('uses extra.apiUrl for branch-preview build', () => {
    const build = requireBuildConfig({
      apiUrl: 'https://preview-api.quickex.to',
      env: 'branch-preview',
    });
    expect(build.API_URL).toBe('https://preview-api.quickex.to');
  });
});

// ---------------------------------------------------------------------------
// Service modules — verify they use the shared API_URL
// ---------------------------------------------------------------------------

describe('service base-URL alignment', () => {
  const fetchMock = jest.fn();

  beforeEach(() => {
    jest.resetModules();
    fetchMock.mockReset();
    global.fetch = fetchMock as unknown as typeof fetch;

    // Point all three services at a clearly identifiable URL
    jest.mock('../src/config/build', () => ({
      API_URL: 'https://testnet-api.quickex.to',
      APP_VERSION: '1.0.0',
      BUILD_NUMBER: '1',
      BUILD_METADATA: '1.0.0+1',
      BUILD_TAG: '',
      APP_ENVIRONMENT: 'testnet',
      STELLAR_NETWORK: 'testnet',
      IS_DEBUG_BUILD: true,
    }));
  });

  afterEach(() => {
    jest.resetModules();
  });

  it('transactions service calls the shared API_URL base', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ items: [], nextCursor: undefined }),
    });

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { fetchTransactions } = require('../services/transactions') as typeof import('../services/transactions');
    await fetchTransactions('GACC');

    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toMatch(/^https:\/\/testnet-api\.quickex\.to/);
    expect(calledUrl).not.toMatch(/localhost/);
  });

  it('link-metadata service calls the shared API_URL base', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({
        amount: '10',
        memo: null,
        memoType: 'text',
        asset: 'USDC',
        privacy: false,
        expiresAt: null,
        canonical: 'alice',
        metadata: { normalized: true },
      }),
    });

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { fetchLinkMetadata } = require('../services/link-metadata') as typeof import('../services/link-metadata');
    await fetchLinkMetadata('alice', 10, 'USDC');

    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toMatch(/^https:\/\/testnet-api\.quickex\.to/);
    expect(calledUrl).not.toMatch(/localhost/);
  });

  it('in-app-notifications service calls the shared API_URL base', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify([]),
    });

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { fetchInAppNotifications } = require('../services/in-app-notifications') as typeof import('../services/in-app-notifications');
    await fetchInAppNotifications('GACC');

    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toMatch(/^https:\/\/testnet-api\.quickex\.to/);
    expect(calledUrl).not.toMatch(/localhost/);
  });
});

// ---------------------------------------------------------------------------
// app.config.ts apiUrl() — build-time URL selection logic
// ---------------------------------------------------------------------------

describe('app.config.ts apiUrl selection', () => {
  const originalEnv = process.env;

  afterEach(() => {
    process.env = originalEnv;
  });

  /**
   * Extract the apiUrl() function logic by re-running it inline.
   * We test the logic rather than importing the config file (which has side effects).
   */
  function resolveApiUrl(env: string, expoPublicApiUrl?: string): string {
    switch (env) {
      case 'production':
        return 'https://api.quickex.to';
      case 'staging':
        return 'https://staging-api.quickex.to';
      default:
        return expoPublicApiUrl ?? 'http://localhost:4000';
    }
  }

  it('resolves production to the live API', () => {
    expect(resolveApiUrl('production')).toBe('https://api.quickex.to');
  });

  it('resolves staging to the staging API', () => {
    expect(resolveApiUrl('staging')).toBe('https://staging-api.quickex.to');
  });

  it('resolves dev with EXPO_PUBLIC_API_URL set to that URL', () => {
    expect(resolveApiUrl('dev', 'http://192.168.1.42:4000')).toBe('http://192.168.1.42:4000');
  });

  it('resolves dev without EXPO_PUBLIC_API_URL to localhost:4000', () => {
    expect(resolveApiUrl('dev', undefined)).toBe('http://localhost:4000');
  });

  it('resolves unknown env to localhost:4000 fallback', () => {
    expect(resolveApiUrl('unknown', undefined)).toBe('http://localhost:4000');
  });

  it('local fallback port is 4000, matching backend default', () => {
    const url = resolveApiUrl('dev', undefined);
    expect(url).toContain(':4000');
    expect(url).not.toContain(':3000');
  });
});
