import React from 'react';
import { render } from '@testing-library/react-native';
import { ThemeProvider } from '../src/context/ThemeContext';
import { PaymentScreen } from '../src/screens/PaymentScreen';
import { ReceiptScreen } from '../src/screens/ReceiptScreen';
import { SettingsScreen } from '../src/screens/SettingsScreen';
import { NotificationScreen } from '../src/screens/NotificationScreen';

const mockReceipt = {
  id: 'test-123',
  amount: '100.00',
  asset: 'USDC',
  sender: 'GABCDEF...123456',
  timestamp: '2026-06-25 14:30',
  status: 'success' as const,
  memo: 'Test payment',
};

function renderWithTheme(component: React.ReactElement, mode: 'light' | 'dark' | 'system' = 'light') {
  // Mock Appearance for testing
  jest.mock('react-native/Libraries/Utilities/Appearance', () => ({
    getColorScheme: () => (mode === 'dark' ? 'dark' : 'light'),
    addChangeListener: () => ({ remove: () => {} }),
  }));

  return render(
    <ThemeProvider>{component}</ThemeProvider>
  );
}

describe('Theme Consistency Screenshots', () => {
  it('PaymentScreen renders correctly in light theme', () => {
    const { toJSON } = renderWithTheme(<PaymentScreen />, 'light');
    expect(toJSON()).toMatchSnapshot('payment-light');
  });

  it('PaymentScreen renders correctly in dark theme', () => {
    const { toJSON } = renderWithTheme(<PaymentScreen />, 'dark');
    expect(toJSON()).toMatchSnapshot('payment-dark');
  });

  it('ReceiptScreen renders correctly in light theme', () => {
    const { toJSON } = renderWithTheme(<ReceiptScreen receipt={mockReceipt} />, 'light');
    expect(toJSON()).toMatchSnapshot('receipt-light');
  });

  it('ReceiptScreen renders correctly in dark theme', () => {
    const { toJSON } = renderWithTheme(<ReceiptScreen receipt={mockReceipt} />, 'dark');
    expect(toJSON()).toMatchSnapshot('receipt-dark');
  });

  it('SettingsScreen renders correctly in light theme', () => {
    const { toJSON } = renderWithTheme(<SettingsScreen />, 'light');
    expect(toJSON()).toMatchSnapshot('settings-light');
  });

  it('SettingsScreen renders correctly in dark theme', () => {
    const { toJSON } = renderWithTheme(<SettingsScreen />, 'dark');
    expect(toJSON()).toMatchSnapshot('settings-dark');
  });

  it('NotificationScreen renders correctly in light theme', () => {
    const { toJSON } = renderWithTheme(<NotificationScreen />, 'light');
    expect(toJSON()).toMatchSnapshot('notification-light');
  });

  it('NotificationScreen renders correctly in dark theme', () => {
    const { toJSON } = renderWithTheme(<NotificationScreen />, 'dark');
    expect(toJSON()).toMatchSnapshot('notification-dark');
  });
});