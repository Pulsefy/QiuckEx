import AsyncStorage from '@react-native-async-storage/async-storage';

import type { EnvironmentId } from '../src/config/environment';
import { DEFAULT_ENVIRONMENT } from '../src/config/environment';

const STORAGE_KEY = '@quickex/environment';

export async function loadEnvironment(): Promise<EnvironmentId> {
  try {
    const raw = await AsyncStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_ENVIRONMENT;
    const parsed = JSON.parse(raw) as { environmentId: EnvironmentId };
    if (isValidEnvironmentId(parsed.environmentId)) {
      return parsed.environmentId;
    }
    return DEFAULT_ENVIRONMENT;
  } catch {
    return DEFAULT_ENVIRONMENT;
  }
}

export async function saveEnvironment(environmentId: EnvironmentId): Promise<void> {
  try {
    await AsyncStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ environmentId }),
    );
  } catch {
    // Swallow — preference will be re-read on next launch.
  }
}

export async function resetEnvironment(): Promise<void> {
  try {
    await AsyncStorage.removeItem(STORAGE_KEY);
  } catch {
    // Swallow
  }
}

function isValidEnvironmentId(id: string): id is EnvironmentId {
  return ['production', 'staging', 'testnet', 'branch-preview'].includes(id);
}
