import { Platform } from 'react-native';
import { API_URL, APP_VERSION } from '../src/config/build';

export type VersionCheckResult = {
  status: 'ok' | 'force_upgrade' | 'optional_upgrade';
  latestVersion: string;
  releaseNotes: string[];
  storeUrl: string;
  message?: string;
};

type RuntimeMobileVersionPolicy = {
  minSupportedVersion?: string;
  recommendedVersion?: string;
  latestVersion?: string;
  iosStoreUrl?: string;
  androidStoreUrl?: string;
  releaseNotes?: string[];
};

type RuntimeConfigResponse = {
  minAppVersion?: string;
  mobileVersionPolicy?: RuntimeMobileVersionPolicy;
};

export class VersionCheckService {
  static async checkVersion(): Promise<VersionCheckResult> {
    try {
      const config = await this.fetchRuntimeConfig();
      const policy = config.mobileVersionPolicy ?? {};
      const minSupportedVersion = policy.minSupportedVersion ?? config.minAppVersion ?? '0.0.0';
      const recommendedVersion = policy.recommendedVersion ?? minSupportedVersion;
      const latestVersion = policy.latestVersion ?? recommendedVersion;
      const releaseNotes = policy.releaseNotes ?? [];
      const storeUrl = Platform.OS === 'ios' ? policy.iosStoreUrl : policy.androidStoreUrl;
      const resolvedStoreUrl = storeUrl ?? '';

      if (this.compareVersions(APP_VERSION, minSupportedVersion) < 0) {
        return {
          status: 'force_upgrade',
          latestVersion,
          releaseNotes,
          storeUrl: resolvedStoreUrl,
          message: `Version ${APP_VERSION} is no longer supported. Update to ${minSupportedVersion} or later to continue.`,
        };
      }

      if (this.compareVersions(APP_VERSION, recommendedVersion) < 0) {
        return {
          status: 'optional_upgrade',
          latestVersion,
          releaseNotes,
          storeUrl: resolvedStoreUrl,
          message: `Version ${recommendedVersion} is recommended for the best QuickEx experience.`,
        };
      }

      return {
        status: 'ok',
        latestVersion,
        releaseNotes,
        storeUrl: resolvedStoreUrl,
      };
    } catch {
      return this.allowOnFailure();
    }
  }

  private static async fetchRuntimeConfig(): Promise<RuntimeConfigResponse> {
    const response = await fetch(`${API_URL.replace(/\/$/, '')}/v1/runtime-config`);
    if (!response.ok) {
      throw new Error(`Version policy request failed with ${response.status}`);
    }
    return response.json();
  }

  static getStatusForPolicy(
    currentVersion: string,
    policy: Required<RuntimeMobileVersionPolicy>,
  ): VersionCheckResult['status'] {
    if (this.compareVersions(currentVersion, policy.minSupportedVersion) < 0) {
      return 'force_upgrade';
    }
    if (this.compareVersions(currentVersion, policy.recommendedVersion) < 0) {
      return 'optional_upgrade';
    }
    return 'ok';
  }

  static allowOnFailure(): VersionCheckResult {
    return {
      status: 'ok',
      latestVersion: APP_VERSION,
      releaseNotes: [],
      storeUrl: '',
    };
  }

  // Helper to compare semver versions
  static compareVersions(v1: string, v2: string): number {
    const p1 = v1.split('.').map(Number);
    const p2 = v2.split('.').map(Number);
    for (let i = 0; i < 3; i++) {
      if ((p1[i] || 0) > (p2[i] || 0)) return 1;
      if ((p1[i] || 0) < (p2[i] || 0)) return -1;
    }
    return 0;
  }
}
