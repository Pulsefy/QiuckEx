import AsyncStorage from '@react-native-async-storage/async-storage';
import { Platform } from 'react-native';
import Constants from 'expo-constants';

export interface AppVersion {
  version: string;
  releaseDate: string;
  releaseNotes: string[];
  minRequiredVersion: string;
  downloadUrl: string;
}

export interface UpdateCheckResult {
  currentVersion: string;
  latestVersion: string;
  isUpdateAvailable: boolean;
  isForceUpdate: boolean;
  releaseNotes: string[];
  downloadUrl: string;
}

export interface UpdateHistory {
  version: string;
  installedDate: string;
  releaseNotes: string[];
}

const UPDATE_HISTORY_KEY = 'quickex.update_history';
const LAST_UPDATE_CHECK_KEY = 'quickex.last_update_check';
const SKIPPED_VERSION_KEY = 'quickex.skipped_version';

// Mock version data - in production, this would come from your backend API
const VERSION_DATA: Record<string, AppVersion> = {
  '1.0.0': {
    version: '1.0.0',
    releaseDate: '2024-01-15',
    releaseNotes: ['Initial release'],
    minRequiredVersion: '1.0.0',
    downloadUrl: 'https://apps.apple.com/app/quickex',
  },
  '1.1.0': {
    version: '1.1.0',
    releaseDate: '2024-02-20',
    releaseNotes: [
      'Added biometric authentication',
      'Improved transaction history',
      'Security patches',
    ],
    minRequiredVersion: '1.0.0',
    downloadUrl: 'https://apps.apple.com/app/quickex',
  },
  '1.2.0': {
    version: '1.2.0',
    releaseDate: '2024-03-10',
    releaseNotes: [
      'Critical security fix',
      'Enhanced QR code scanning',
      'Performance improvements',
    ],
    minRequiredVersion: '1.1.0',
    downloadUrl: 'https://apps.apple.com/app/quickex',
  },
  '2.0.0': {
    version: '2.0.0',
    releaseDate: '2024-04-01',
    releaseNotes: [
      'Major redesign with new UI',
      'Added crash reporting',
      'Multi-network support',
      'Enhanced security features',
    ],
    minRequiredVersion: '1.2.0',
    downloadUrl: 'https://apps.apple.com/app/quickex',
  },
};

export class AppUpdateService {
  static getCurrentVersion(): string {
    return Constants.expoConfig?.version || '1.0.0';
  }

  static getLatestVersion(): string {
    const versions = Object.keys(VERSION_DATA).sort((a, b) => {
      const aParts = a.split('.').map(Number);
      const bParts = b.split('.').map(Number);
      for (let i = 0; i < 3; i++) {
        if ((aParts[i] || 0) !== (bParts[i] || 0)) {
          return (aParts[i] || 0) - (bParts[i] || 0);
        }
      }
      return 0;
    });
    return versions[versions.length - 1] || '1.0.0';
  }

  static compareVersions(v1: string, v2: string): number {
    const p1 = v1.split('.').map(Number);
    const p2 = v2.split('.').map(Number);
    for (let i = 0; i < 3; i++) {
      if ((p1[i] || 0) > (p2[i] || 0)) return 1;
      if ((p1[i] || 0) < (p2[i] || 0)) return -1;
    }
    return 0;
  }

  static async checkForUpdates(): Promise<UpdateCheckResult> {
    const currentVersion = this.getCurrentVersion();
    const latestVersion = this.getLatestVersion();
    const versionData = VERSION_DATA[latestVersion];

    const isUpdateAvailable = this.compareVersions(latestVersion, currentVersion) > 0;
    const isForceUpdate = isUpdateAvailable &&
      versionData &&
      this.compareVersions(currentVersion, versionData.minRequiredVersion) < 0;

    await AsyncStorage.setItem(
      LAST_UPDATE_CHECK_KEY,
      JSON.stringify({ timestamp: Date.now(), version: latestVersion }),
    );

    return {
      currentVersion,
      latestVersion,
      isUpdateAvailable,
      isForceUpdate,
      releaseNotes: versionData?.releaseNotes || [],
      downloadUrl: versionData?.downloadUrl || '',
    };
  }

  static async getUpdateHistory(): Promise<UpdateHistory[]> {
    try {
      const stored = await AsyncStorage.getItem(UPDATE_HISTORY_KEY);
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  }

  static async addToUpdateHistory(version: string, releaseNotes: string[]) {
    try {
      const history = await this.getUpdateHistory();
      history.push({
        version,
        installedDate: new Date().toISOString(),
        releaseNotes,
      });

      if (history.length > 20) {
        history.shift();
      }

      await AsyncStorage.setItem(UPDATE_HISTORY_KEY, JSON.stringify(history));
    } catch (e) {
      console.error('Failed to add to update history:', e);
    }
  }

  static async skipVersion(version: string) {
    try {
      await AsyncStorage.setItem(SKIPPED_VERSION_KEY, version);
    } catch (e) {
      console.error('Failed to skip version:', e);
    }
  }

  static async getSkippedVersion(): Promise<string | null> {
    try {
      return await AsyncStorage.getItem(SKIPPED_VERSION_KEY);
    } catch {
      return null;
    }
  }

  static async shouldShowUpdatePrompt(): Promise<boolean> {
    try {
      const result = await this.checkForUpdates();
      if (!result.isUpdateAvailable) return false;

      const skipped = await this.getSkippedVersion();
      return skipped !== result.latestVersion;
    } catch {
      return false;
    }
  }
}
