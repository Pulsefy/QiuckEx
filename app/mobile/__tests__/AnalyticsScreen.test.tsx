/**
 * Analytics screen test coverage
 *
 * Tests successful data rendering and API failure fallback states
 * for the mobile analytics screen as per acceptance criteria.
 */
import { render, screen, waitFor, fireEvent } from '@testing-library/react-native';
import React from 'react';

import AnalyticsScreen from '../app/analytics';
import { QuickExThemeProvider } from '../src/theme/ThemeContext';
import * as analyticsApi from '../src/services/analyticsApi';

// Mock analytics API
jest.mock('../src/services/analyticsApi', () => ({
  fetchAnalytics: jest.fn(),
  exportAnalyticsReport: jest.fn(),
  clearAnalyticsCache: jest.fn(),
}));

// Mock Ionicons
jest.mock('@expo/vector-icons', () => ({
  Ionicons: 'Ionicons',
}));

// Mock expo-router
jest.mock('expo-router', () => ({
  useRouter: jest.fn(() => ({
    back: jest.fn(),
    push: jest.fn(),
    replace: jest.fn(),
  })),
  useLocalSearchParams: jest.fn(() => ({})),
}));

// Mock wallet context
jest.mock('../hooks/useWalletContext', () => ({
  useWalletContext: jest.fn(),
  WalletProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

// Mock environment context
jest.mock('../contexts/EnvironmentContext', () => ({
  useEnvironment: jest.fn(() => ({ currentId: 'production' })),
  EnvironmentProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

// Mock session context
jest.mock('../contexts/SessionContext', () => ({
  SessionProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

const mockUseWalletContext = require('../hooks/useWalletContext').useWalletContext;

describe('Analytics Screen', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  function renderAnalyticsScreen() {
    return render(
      <QuickExThemeProvider>
        <AnalyticsScreen />
      </QuickExThemeProvider>,
    );
  }

  describe('Loading State', () => {
    it('shows loading indicator when fetching analytics', () => {
      mockUseWalletContext.mockReturnValue({
        wallet: {
          connected: true,
          publicKey: 'GTEST1234567890abcdefghij',
          network: 'testnet',
          walletType: 'demo',
          connectedAt: Date.now(),
          error: undefined,
          isRestoring: false,
        },
      });

      (analyticsApi.fetchAnalytics as jest.Mock).mockImplementation(
        () => new Promise(() => {}), // Never resolves to keep loading state
      );

      renderAnalyticsScreen();

      expect(screen.getByText('Loading analytics...')).toBeTruthy();
    });
  });

  describe('Successful Data Rendering', () => {
    it('renders analytics data successfully when API returns valid data', async () => {
      mockUseWalletContext.mockReturnValue({
        wallet: {
          connected: true,
          publicKey: 'GTEST1234567890abcdefghij',
          network: 'testnet',
          walletType: 'demo',
          connectedAt: Date.now(),
          error: undefined,
          isRestoring: false,
        },
      });

      const mockAnalyticsData = {
        volume: [
          { date: '2026-01-01', volumeUSDC: 1000, volumeXLM: 500, total: 1500 },
          { date: '2026-01-02', volumeUSDC: 1200, volumeXLM: 600, total: 1800 },
        ],
        txCount: [
          { date: '2026-01-01', count: 10 },
          { date: '2026-01-02', count: 12 },
        ],
        assetDist: [
          { name: 'USDC', value: 60, color: '#6366f1' },
          { name: 'XLM', value: 40, color: '#8b5cf6' },
        ],
        summary: {
          totalVolume: 3300,
          totalTx: 22,
          avgTxSize: 150,
          changeVolumePercent: 10,
          successfulTx: 20,
          failedTx: 2,
          conversionRate: 90.9,
          refundCount: 2,
          refundVolume: 300,
        },
      };

      (analyticsApi.fetchAnalytics as jest.Mock).mockResolvedValue(mockAnalyticsData);

      renderAnalyticsScreen();

      await waitFor(() => {
        expect(screen.queryByText('Loading analytics...')).toBeNull();
      });

      // Verify summary stats are rendered
      expect(screen.getByText(/\$3,300/)).toBeTruthy(); // Total volume
      expect(screen.getByText(/22/)).toBeTruthy(); // Total transactions
      expect(screen.getByText(/\$150/)).toBeTruthy(); // Average transaction size
      expect(screen.getByText(/90\.9%/)).toBeTruthy(); // Success rate

      // Verify asset distribution is rendered
      expect(screen.getByText('USDC')).toBeTruthy();
      expect(screen.getByText('XLM')).toBeTruthy();
      expect(screen.getByText('60%')).toBeTruthy();
      expect(screen.getByText('40%')).toBeTruthy();

      // Verify transaction volume data is rendered
      expect(screen.getByText('2026-01-01')).toBeTruthy();
      expect(screen.getByText('2026-01-02')).toBeTruthy();

      // Verify export buttons are present
      expect(screen.getByText('Export CSV')).toBeTruthy();
      expect(screen.getByText('Export PDF')).toBeTruthy();
    });
  });

  describe('API Failure Fallback', () => {
    it('shows error state when API request fails', async () => {
      mockUseWalletContext.mockReturnValue({
        wallet: {
          connected: true,
          publicKey: 'GTEST1234567890abcdefghij',
          network: 'testnet',
          walletType: 'demo',
          connectedAt: Date.now(),
          error: undefined,
          isRestoring: false,
        },
      });

      (analyticsApi.fetchAnalytics as jest.Mock).mockRejectedValue(
        new Error('Network error'),
      );

      renderAnalyticsScreen();

      await waitFor(() => {
        expect(screen.queryByText('Loading analytics...')).toBeNull();
      });

      expect(screen.getByText(/Network error/)).toBeTruthy();
    });

    it('shows empty state when no wallet is connected', () => {
      mockUseWalletContext.mockReturnValue({
        wallet: {
          connected: false,
          publicKey: undefined,
          network: 'testnet',
          walletType: undefined,
          connectedAt: undefined,
          error: undefined,
          isRestoring: false,
        },
      });

      renderAnalyticsScreen();

      expect(screen.getByText('No wallet connected')).toBeTruthy();
      expect(
        screen.getByText('Connect your wallet to view analytics'),
      ).toBeTruthy();
    });

    it('gracefully handles empty analytics data', async () => {
      mockUseWalletContext.mockReturnValue({
        wallet: {
          connected: true,
          publicKey: 'GTEST1234567890abcdefghij',
          network: 'testnet',
          walletType: 'demo',
          connectedAt: Date.now(),
          error: undefined,
          isRestoring: false,
        },
      });

      const emptyData = {
        volume: [],
        txCount: [],
        assetDist: [],
        summary: {
          totalVolume: 0,
          totalTx: 0,
          avgTxSize: 0,
          changeVolumePercent: 0,
          successfulTx: 0,
          failedTx: 0,
          conversionRate: 100,
          refundCount: 0,
          refundVolume: 0,
        },
      };

      (analyticsApi.fetchAnalytics as jest.Mock).mockResolvedValue(emptyData);

      renderAnalyticsScreen();

      await waitFor(() => {
        expect(screen.queryByText('Loading analytics...')).toBeNull();
      });

      // Should render with zero values instead of crashing
      expect(screen.getByText('$0')).toBeTruthy();
      expect(screen.getByText('0')).toBeTruthy();
      expect(screen.getByText('100%')).toBeTruthy();
      expect(screen.getByText('No asset data available')).toBeTruthy();
      expect(screen.getByText('No volume data available')).toBeTruthy();
      expect(screen.getByText('No transaction count data available')).toBeTruthy();
    });
  });

  describe('Export Functionality', () => {
    it('calls export API with correct parameters when CSV export is triggered', async () => {
      mockUseWalletContext.mockReturnValue({
        wallet: {
          connected: true,
          publicKey: 'GTEST1234567890abcdefghij',
          network: 'testnet',
          walletType: 'demo',
          connectedAt: Date.now(),
          error: undefined,
          isRestoring: false,
        },
      });

      const mockAnalyticsData = {
        volume: [],
        txCount: [],
        assetDist: [],
        summary: {
          totalVolume: 0,
          totalTx: 0,
          avgTxSize: 0,
          changeVolumePercent: 0,
          successfulTx: 0,
          failedTx: 0,
          conversionRate: 100,
          refundCount: 0,
          refundVolume: 0,
        },
      };

      (analyticsApi.fetchAnalytics as jest.Mock).mockResolvedValue(mockAnalyticsData);
      (analyticsApi.exportAnalyticsReport as jest.Mock).mockResolvedValue(undefined);

      renderAnalyticsScreen();

      await waitFor(() => {
        expect(screen.queryByText('Loading analytics...')).toBeNull();
      });

      const csvButton = screen.getByText('Export CSV');
      fireEvent.press(csvButton);

      await waitFor(() => {
        expect(analyticsApi.exportAnalyticsReport).toHaveBeenCalledWith(
          'GTEST1234567890abcdefghij',
          '30d',
          'csv',
          'accounting',
          'production',
        );
      });
    });

    it('calls export API with correct parameters when PDF export is triggered', async () => {
      mockUseWalletContext.mockReturnValue({
        wallet: {
          connected: true,
          publicKey: 'GTEST1234567890abcdefghij',
          network: 'testnet',
          walletType: 'demo',
          connectedAt: Date.now(),
          error: undefined,
          isRestoring: false,
        },
      });

      const mockAnalyticsData = {
        volume: [],
        txCount: [],
        assetDist: [],
        summary: {
          totalVolume: 0,
          totalTx: 0,
          avgTxSize: 0,
          changeVolumePercent: 0,
          successfulTx: 0,
          failedTx: 0,
          conversionRate: 100,
          refundCount: 0,
          refundVolume: 0,
        },
      };

      (analyticsApi.fetchAnalytics as jest.Mock).mockResolvedValue(mockAnalyticsData);
      (analyticsApi.exportAnalyticsReport as jest.Mock).mockResolvedValue(undefined);

      renderAnalyticsScreen();

      await waitFor(() => {
        expect(screen.queryByText('Loading analytics...')).toBeNull();
      });

      const pdfButton = screen.getByText('Export PDF');
      fireEvent.press(pdfButton);

      await waitFor(() => {
        expect(analyticsApi.exportAnalyticsReport).toHaveBeenCalledWith(
          'GTEST1234567890abcdefghij',
          '30d',
          'pdf',
          'accounting',
          'production',
        );
      });
    });
  });

  describe('Date Range Filter', () => {
    it('switches date range and fetches new data', async () => {
      mockUseWalletContext.mockReturnValue({
        wallet: {
          connected: true,
          publicKey: 'GTEST1234567890abcdefghij',
          network: 'testnet',
          walletType: 'demo',
          connectedAt: Date.now(),
          error: undefined,
          isRestoring: false,
        },
      });

      const mockAnalyticsData = {
        volume: [],
        txCount: [],
        assetDist: [],
        summary: {
          totalVolume: 0,
          totalTx: 0,
          avgTxSize: 0,
          changeVolumePercent: 0,
          successfulTx: 0,
          failedTx: 0,
          conversionRate: 100,
          refundCount: 0,
          refundVolume: 0,
        },
      };

      (analyticsApi.fetchAnalytics as jest.Mock).mockResolvedValue(mockAnalyticsData);

      renderAnalyticsScreen();

      await waitFor(() => {
        expect(screen.queryByText('Loading analytics...')).toBeNull();
      });

      // Initially called with default 30d range
      expect(analyticsApi.fetchAnalytics).toHaveBeenCalledWith(
        'GTEST1234567890abcdefghij',
        '30d',
        'production',
      );

      // Click on 7d range
      const sevenDayButton = screen.getByText('7d');
      fireEvent.press(sevenDayButton);

      await waitFor(() => {
        expect(analyticsApi.fetchAnalytics).toHaveBeenCalledWith(
          'GTEST1234567890abcdefghij',
          '7d',
          'production',
        );
      });
    });
  });
});