import { Platform } from 'react-native';

import { VersionCheckService } from '../services/VersionCheckService';

jest.mock('../src/config/build', () => ({
  API_URL: 'https://api.quickex.test',
  APP_VERSION: '1.2.0',
}));

function mockRuntimeConfig(policy: {
  minSupportedVersion: string;
  recommendedVersion: string;
  latestVersion: string;
}) {
  (global.fetch as jest.Mock).mockResolvedValue({
    ok: true,
    json: async () => ({
      mobileVersionPolicy: {
        ...policy,
        iosStoreUrl: 'https://apps.apple.com/app/quickex',
        androidStoreUrl: 'market://details?id=com.pulsefy.quickex',
        releaseNotes: ['Security fixes', 'Contract registry compatibility'],
      },
    }),
  });
}

describe('VersionCheckService', () => {
  beforeEach(() => {
    global.fetch = jest.fn();
    Object.defineProperty(Platform, 'OS', {
      value: 'ios',
      configurable: true,
    });
  });

  it('blocks clients below the server minimum supported version', async () => {
    mockRuntimeConfig({
      minSupportedVersion: '1.3.0',
      recommendedVersion: '1.4.0',
      latestVersion: '1.4.1',
    });

    const result = await VersionCheckService.checkVersion();

    expect(result.status).toBe('force_upgrade');
    expect(result.storeUrl).toBe('https://apps.apple.com/app/quickex');
    expect(result.message).toContain('no longer supported');
  });

  it('soft-prompts clients below the recommended version without blocking', async () => {
    mockRuntimeConfig({
      minSupportedVersion: '1.0.0',
      recommendedVersion: '1.3.0',
      latestVersion: '1.3.1',
    });

    const result = await VersionCheckService.checkVersion();

    expect(result.status).toBe('optional_upgrade');
    expect(result.latestVersion).toBe('1.3.1');
    expect(result.releaseNotes).toContain('Security fixes');
  });

  it('allows clients at or above the recommended version', async () => {
    mockRuntimeConfig({
      minSupportedVersion: '1.0.0',
      recommendedVersion: '1.2.0',
      latestVersion: '1.2.0',
    });

    const result = await VersionCheckService.checkVersion();

    expect(result.status).toBe('ok');
  });

  it('defaults to allow when the version check fails', async () => {
    (global.fetch as jest.Mock).mockRejectedValue(new Error('network unavailable'));

    const result = await VersionCheckService.checkVersion();

    expect(result.status).toBe('ok');
    expect(result.latestVersion).toBe('1.2.0');
  });
});
