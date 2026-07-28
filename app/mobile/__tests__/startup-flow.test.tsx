import React from 'react';
import { render, screen, waitFor } from '@testing-library/react-native';
import { Text } from 'react-native';
import { SessionProvider, useSession } from '../contexts/SessionContext';
import { EnvironmentProvider, useEnvironment } from '../contexts/EnvironmentContext';
import { fetchSessionBootstrap } from '../services/session-bootstrap';

jest.mock('../services/session-bootstrap', () => ({
  fetchSessionBootstrap: jest.fn(),
}));

jest.mock('../services/environment-storage', () => ({
  loadEnvironment: jest.fn().mockResolvedValue('testnet'),
  saveEnvironment: jest.fn(),
  resetEnvironment: jest.fn(),
}));

function TestComponent() {
  const { data, isReady, error } = useSession();
  const { metadata } = useEnvironment();
  
  return (
    <>
      <Text testID="ready">{isReady ? 'Yes' : 'No'}</Text>
      <Text testID="unread">{data?.unreadCount ?? 'none'}</Text>
      <Text testID="metadata">{metadata?.appVersion ?? 'none'}</Text>
      <Text testID="error">{error ? 'error' : 'none'}</Text>
    </>
  );
}

describe('Startup Flow: SessionProvider', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('handles authenticated startup', async () => {
    const mockResponse = {
      metadata: { appVersion: '2.0.0', minAppVersion: '1.0.0' },
      unreadCount: 42,
      featureFlags: {},
      accountContext: { publicKey: 'G_TEST' },
    };
    (fetchSessionBootstrap as jest.Mock).mockResolvedValue(mockResponse);

    const { getByTestId } = render(
      <EnvironmentProvider>
        <SessionProvider>
          <TestComponent />
        </SessionProvider>
      </EnvironmentProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('ready').props.children).toBe('Yes');
    });

    expect(screen.getByTestId('unread').props.children).toBe(42);
    expect(screen.getByTestId('metadata').props.children).toBe('2.0.0');
    expect(screen.getByTestId('error').props.children).toBe('none');
  });

  it('handles guest startup (no account context)', async () => {
    const mockResponse = {
      metadata: { appVersion: '2.0.0', minAppVersion: '1.0.0' },
      unreadCount: 0,
      featureFlags: {},
      accountContext: null,
    };
    (fetchSessionBootstrap as jest.Mock).mockResolvedValue(mockResponse);

    const { getByTestId } = render(
      <EnvironmentProvider>
        <SessionProvider>
          <TestComponent />
        </SessionProvider>
      </EnvironmentProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('ready').props.children).toBe('Yes');
    });

    expect(screen.getByTestId('unread').props.children).toBe(0);
    expect(screen.getByTestId('metadata').props.children).toBe('2.0.0');
    expect(screen.getByTestId('error').props.children).toBe('none');
  });

  it('gracefully handles bootstrap failure', async () => {
    (fetchSessionBootstrap as jest.Mock).mockRejectedValue(new Error('Network error'));

    const { getByTestId } = render(
      <EnvironmentProvider>
        <SessionProvider>
          <TestComponent />
        </SessionProvider>
      </EnvironmentProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('ready').props.children).toBe('Yes');
    });

    expect(screen.getByTestId('unread').props.children).toBe('none');
    expect(screen.getByTestId('metadata').props.children).toBe('none');
    expect(screen.getByTestId('error').props.children).toBe('error');
  });
});
