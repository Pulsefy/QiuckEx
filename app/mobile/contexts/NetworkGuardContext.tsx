import React, { createContext, useContext, ReactNode } from 'react';
import { useNetworkGuard, NetworkGuardState, NetworkGuardConfig } from '../hooks/useNetworkGuard';
import { StellarNetwork } from '../types/wallet';

interface NetworkGuardContextType {
  guard: NetworkGuardState;
  config: NetworkGuardConfig;
}

const NetworkGuardContext = createContext<NetworkGuardContextType | undefined>(undefined);

/**
 * Provider that distributes network guard state throughout the app.
 * Must be placed AFTER WalletProvider.
 */
export const NetworkGuardProvider: React.FC<{
  children: ReactNode;
  expectedNetwork?: StellarNetwork;
  listenForNetworkEvents?: boolean;
  listenForFocusEvents?: boolean;
}> = ({
  children,
  expectedNetwork = 'testnet',
  listenForNetworkEvents = true,
  listenForFocusEvents = true,
}) => {
  const guard = useNetworkGuard(expectedNetwork);

  const value = {
    guard,
    config: {
      expectedNetwork,
      listenForNetworkEvents,
      listenForFocusEvents,
    },
  };

  return (
    <NetworkGuardContext.Provider value={value}>
      {children}
    </NetworkGuardContext.Provider>
  );
};

export const useNetworkGuardContext = () => {
  const context = useContext(NetworkGuardContext);
  if (context === undefined) {
    throw new Error('useNetworkGuardContext must be used within a NetworkGuardProvider');
  }
  return context;
};