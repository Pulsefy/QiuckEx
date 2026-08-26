import React from 'react';
import { render, fireEvent } from '@testing-library/react-native';
import PaymentConfirmationScreen from '../app/payment-confirmation';
import { NetworkGuardProvider } from '../contexts/NetworkGuardContext';
import { useWalletContext } from '../hooks/useWalletContext';
import { useNetworkStatus } from '../hooks/use-network-status';
import { useSecurity } from '../hooks/use-security';

jest.mock('expo-router', () => ({
  useRouter: () => ({ back: jest.fn(), replace: jest.fn() }),
  useLocalSearchParams: () => ({
    username: 'alice',
    amount: '100',
    asset: 'XLM',
  }),
}));

jest.mock('../src/theme/ThemeContext', () => ({
  useTheme: () => ({ theme: { background: '#fff' } }),
}));

jest.mock('../hooks/use-network-status', () => ({
  useNetworkStatus: jest.fn(),
}));

jest.mock('../hooks/use-security', () => ({
  useSecurity: jest.fn(),
}));

jest.mock('../hooks/use-swap-options', () => ({
  useSwapOptions: () => ({ swapOptions: [], loading: false, isExpired: false, refetch: jest.fn() }),
}));

jest.mock('../hooks/useContractRegistry', () => ({
  useContractRegistry: () => ({ isReady: true, missingContracts: [] }),
}));

jest.mock('../contexts/SessionContext', () => ({
  useSession: () => ({ data: {} }),
}));

jest.mock('../hooks/useWalletContext', () => {
  const React = require('react');
  const mockWalletState = {
    connected: true,
    publicKey: 'GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP',
    network: 'mainnet',
    walletType: 'freighter',
  };
  return {
    useWalletContext: jest.fn(() => ({ wallet: mockWalletState })),
  };
});

describe('PaymentConfirmationScreen Network Mismatch', () => {
  beforeEach(() => {
    (useNetworkStatus as jest.Mock).mockReturnValue({ isConnected: true });
    (useSecurity as jest.Mock).mockReturnValue({ authenticateForSensitiveAction: jest.fn().mockResolvedValue(true) });
  });

  it('blocks payment when network is mismatched and shows recovery guidance', () => {
    const { getByText } = render(
      <NetworkGuardProvider expectedNetwork="testnet">
        <PaymentConfirmationScreen />
      </NetworkGuardProvider>
    );
    
    const payBtn = getByText('Action Blocked');
    expect(payBtn).toBeTruthy();
    
    fireEvent.press(payBtn);
    
    expect(getByText('Mismatch Detected')).toBeTruthy();
    expect(getByText(/Your wallet is on MAINNET but this action requires TESTNET/i)).toBeTruthy();
  });
});
