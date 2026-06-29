import React from 'react';
import { render, fireEvent, waitFor } from '@testing-library/react-native';
import { ThemeProvider } from '../../../context/ThemeContext';
import { MetadataSection } from '../MetadataSection';

const mockMetadata = {
  receiptHash: '0xabc123def4567890123456789012345678901234abcdef5678901234567890ab',
  createdAt: '2026-06-25 14:30:00 UTC',
  expiresAt: '2026-06-25 15:30:00 UTC',
};

const mockContract = {
  contractId: 'C1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
  wasmHash: '0xwasm7890123456789012345678901234567890123456789012345678901234',
  deployedAt: '2026-01-15 10:00:00 UTC',
  networkPassphrase: 'Test SDF Network ; September 2015',
};

const mockNetwork = {
  network: 'testnet' as const,
  horizonUrl: 'https://horizon-testnet.stellar.org',
  ledger: 1234567,
  ledgerCloseTime: '2026-06-25 14:30:15 UTC',
};

function renderWithTheme(component: React.ReactElement) {
  return render(<ThemeProvider>{component}</ThemeProvider>);
}

describe('MetadataSection', () => {
  it('renders receipt hash with copy button', () => {
    const { getByText } = renderWithTheme(
      <MetadataSection
        receiptMetadata={mockMetadata}
        contract={mockContract}
        network={mockNetwork}
      />
    );

    expect(getByText('Transaction Details')).toBeTruthy();
    expect(getByText(/0xabc123/)).toBeTruthy();
  });

  it('expands to show contract metadata', () => {
    const { getByText, queryByText } = renderWithTheme(
      <MetadataSection
        receiptMetadata={mockMetadata}
        contract={mockContract}
        network={mockNetwork}
      />
    );

    expect(queryByText('Contract ID')).toBeNull();

    fireEvent.press(getByText('Transaction Details'));

    waitFor(() => {
      expect(getByText('Contract ID')).toBeTruthy();
      expect(getByText('WASM Hash')).toBeTruthy();
    });
  });

  it('displays network badge with ledger', () => {
    const { getByText } = renderWithTheme(
      <MetadataSection
        receiptMetadata={mockMetadata}
        contract={mockContract}
        network={mockNetwork}
      />
    );

    expect(getByText('Testnet')).toBeTruthy();
    expect(getByText(/Ledger 1,234,567/)).toBeTruthy();
  });
});