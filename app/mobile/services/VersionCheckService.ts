import { Platform } from 'react-native';
import Constants from 'expo-constants';

export type VersionCheckResult = {
  status: 'ok' | 'force_upgrade' | 'optional_upgrade';
  latestVersion: string;
  releaseNotes: string[];
  storeUrl: string;
};

// Mock service for minimal implementation
export class VersionCheckService {
  static async checkVersion(): Promise<VersionCheckResult> {
    const currentVersion = Constants.expoConfig?.version || '1.0.0';
    
    // In a real app, this would be an API call to your backend
    const mockApiResponse = {
      latestVersion: '1.2.0',
      minRequiredVersion: '1.1.0',
      releaseNotes: [
        'Added new security features',
        'Fixed critical bug causing crashes on startup',
        'Improved performance in transaction history'
      ],
      iosStoreUrl: 'https://apps.apple.com/app/id123456789',
      androidStoreUrl: 'market://details?id=com.pulsefy.soter'
    };

    const isForceUpgrade = this.compareVersions(currentVersion, mockApiResponse.minRequiredVersion) < 0;
    const isOptionalUpgrade = !isForceUpgrade && this.compareVersions(currentVersion, mockApiResponse.latestVersion) < 0;

    return {
      status: isForceUpgrade ? 'force_upgrade' : (isOptionalUpgrade ? 'optional_upgrade' : 'ok'),
      latestVersion: mockApiResponse.latestVersion,
      releaseNotes: mockApiResponse.releaseNotes,
      storeUrl: Platform.OS === 'ios' ? mockApiResponse.iosStoreUrl : mockApiResponse.androidStoreUrl,
    };
  }

  // Helper to compare semver versions
  private static compareVersions(v1: string, v2: string): number {
    const p1 = v1.split('.').map(Number);
    const p2 = v2.split('.').map(Number);
    for (let i = 0; i < 3; i++) {
      if ((p1[i] || 0) > (p2[i] || 0)) return 1;
      if ((p1[i] || 0) < (p2[i] || 0)) return -1;
    }
    return 0;
  }
}
