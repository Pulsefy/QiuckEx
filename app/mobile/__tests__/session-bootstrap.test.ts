import { fetchSessionBootstrap } from '../services/session-bootstrap';
import { getWalletSession } from '../services/wallet-session';

jest.mock('../services/wallet-session', () => ({
  getWalletSession: jest.fn(),
}));

describe('fetchSessionBootstrap', () => {
  const apiUrl = 'http://localhost:3000';

  beforeEach(() => {
    jest.resetAllMocks();
    global.fetch = jest.fn();
  });

  it('fetches authenticated data when wallet session exists', async () => {
    (getWalletSession as jest.Mock).mockResolvedValue({ publicKey: 'TEST_KEY' });
    
    const mockResponse = {
      metadata: { version: '1.0.0' },
      unreadCount: 5,
      featureFlags: { newFeature: true },
      accountContext: { publicKey: 'TEST_KEY' },
    };

    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => mockResponse,
    });

    const result = await fetchSessionBootstrap(apiUrl);

    expect(global.fetch).toHaveBeenCalledWith(`${apiUrl}/session/bootstrap`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: 'Bearer TEST_KEY',
      },
    });
    expect(result).toEqual(mockResponse);
  });

  it('fetches guest data when wallet session does not exist', async () => {
    (getWalletSession as jest.Mock).mockResolvedValue(null);
    
    const mockResponse = {
      metadata: { version: '1.0.0' },
      unreadCount: 0,
      featureFlags: { newFeature: false },
      accountContext: null,
    };

    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => mockResponse,
    });

    const result = await fetchSessionBootstrap(apiUrl);

    expect(global.fetch).toHaveBeenCalledWith(`${apiUrl}/session/bootstrap`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
    });
    expect(result).toEqual(mockResponse);
  });

  it('throws an error on non-ok response', async () => {
    (getWalletSession as jest.Mock).mockResolvedValue(null);
    
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ message: 'Server error' }),
    });

    await expect(fetchSessionBootstrap(apiUrl)).rejects.toThrow('Server error');
  });
});
