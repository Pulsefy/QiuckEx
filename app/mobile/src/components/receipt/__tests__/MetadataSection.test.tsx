import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react-native';
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
  it('renders receipt hash with copy button', async () => {
    renderWithTheme(
      <MetadataSection
        receiptMetadata={mockMetadata}
        contract={mockContract}
        network={mockNetwork}
      />
    );

    await waitFor(() => expect(screen.getByText('Transaction Details')).toBeTruthy());
    expect(screen.getByText(/0xabc123/)).toBeTruthy();
  });

  it('expands to show contract metadata', async () => {
    renderWithTheme(
      <MetadataSection
        receiptMetadata={mockMetadata}
        contract={mockContract}
        network={mockNetwork}
      />
    );

    // Initial render is null while ThemeProvider async loads, so wait for it
    await waitFor(() => expect(screen.getByText('Transaction Details')).toBeTruthy());

    expect(screen.queryByText('Contract ID')).toBeNull();

    fireEvent.press(screen.getByText('Transaction Details'));

    await waitFor(() => {
      expect(screen.getByText('Contract ID')).toBeTruthy();
      expect(screen.getByText('WASM Hash')).toBeTruthy();
    });
  });

  it('displays network badge with ledger', async () => {
    renderWithTheme(
      <MetadataSection
        receiptMetadata={mockMetadata}
        contract={mockContract}
        network={mockNetwork}
      />
    );

    await waitFor(() => expect(screen.getByText('Testnet')).toBeTruthy());
    expect(screen.getByText(/Ledger 1,234,567/)).toBeTruthy();
  });
});
