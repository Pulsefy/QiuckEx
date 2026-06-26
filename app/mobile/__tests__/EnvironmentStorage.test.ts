import {
  loadEnvironment,
  saveEnvironment,
  resetEnvironment,
} from '../services/environment-storage';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { DEFAULT_ENVIRONMENT } from '../src/config/environment';

jest.mock('@react-native-async-storage/async-storage', () => ({
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
}));

describe('Environment Storage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('loads default environment when nothing is stored', async () => {
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(null);
    const env = await loadEnvironment();
    expect(env).toBe(DEFAULT_ENVIRONMENT);
  });

  it('persists and loads staging', async () => {
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(
      JSON.stringify({ environmentId: 'staging' }),
    );
    expect(await loadEnvironment()).toBe('staging');
  });

  it('persists and loads testnet', async () => {
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(
      JSON.stringify({ environmentId: 'testnet' }),
    );
    expect(await loadEnvironment()).toBe('testnet');
  });

  it('persists and loads branch-preview', async () => {
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(
      JSON.stringify({ environmentId: 'branch-preview' }),
    );
    expect(await loadEnvironment()).toBe('branch-preview');
  });

  it('calls setItem on save', async () => {
    await saveEnvironment('staging');
    expect(AsyncStorage.setItem).toHaveBeenCalledWith(
      '@quickex/environment',
      JSON.stringify({ environmentId: 'staging' }),
    );
  });

  it('calls removeItem on reset', async () => {
    await resetEnvironment();
    expect(AsyncStorage.removeItem).toHaveBeenCalledWith('@quickex/environment');
  });

  it('falls back to default when stored value is invalid', async () => {
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(
      JSON.stringify({ environmentId: 'invalid-env' }),
    );
    expect(await loadEnvironment()).toBe(DEFAULT_ENVIRONMENT);
  });
});
