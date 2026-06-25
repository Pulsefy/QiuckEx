import React from 'react';
import { render } from '@testing-library/react-native';
import { ThemeProvider } from '../src/context/ThemeContext';
import { ReceiptScreen } from '../src/screens/ReceiptScreen';
import {
  mockReceiptPending,
  mockReceiptSuccess,
  mockReceiptFailed,
  mockReceiptRefund,
} from '../src/data/mockReceipt';

function renderWithTheme(component: React.ReactElement, mode: 'light' | 'dark' = 'light') {
  jest.mock('react-native/Libraries/Utilities/Appearance', () => ({
    getColorScheme: () => mode,
    addChangeListener: () => ({ remove: () => {} }),
  }));

  return render(<ThemeProvider>{component}</ThemeProvider>);
}

describe('ReceiptScreen v3 Screenshots', () => {
  it('renders pending state in light theme', () => {
    const { toJSON } = renderWithTheme(
      <ReceiptScreen receipt={mockReceiptPending} />,
      'light'
    );
    expect(toJSON()).toMatchSnapshot('receipt-pending-light');
  });

  it('renders pending state in dark theme', () => {
    const { toJSON } = renderWithTheme(
      <ReceiptScreen receipt={mockReceiptPending} />,
      'dark'
    );
    expect(toJSON()).toMatchSnapshot('receipt-pending-dark');
  });

  it('renders success state in light theme', () => {
    const { toJSON } = renderWithTheme(
      <ReceiptScreen receipt={mockReceiptSuccess} />,
      'light'
    );
    expect(toJSON()).toMatchSnapshot('receipt-success-light');
  });

  it('renders success state in dark theme', () => {
    const { toJSON } = renderWithTheme(
      <ReceiptScreen receipt={mockReceiptSuccess} />,
      'dark'
    );
    expect(toJSON()).toMatchSnapshot('receipt-success-dark');
  });

  it('renders failed state in light theme', () => {
    const { toJSON } = renderWithTheme(
      <ReceiptScreen receipt={mockReceiptFailed} />,
      'light'
    );
    expect(toJSON()).toMatchSnapshot('receipt-failed-light');
  });

  it('renders failed state in dark theme', () => {
    const { toJSON } = renderWithTheme(
      <ReceiptScreen receipt={mockReceiptFailed} />,
      'dark'
    );
    expect(toJSON()).toMatchSnapshot('receipt-failed-dark');
  });

  it('renders refund state in light theme', () => {
    const { toJSON } = renderWithTheme(
      <ReceiptScreen receipt={mockReceiptRefund} />,
      'light'
    );
    expect(toJSON()).toMatchSnapshot('receipt-refund-light');
  });

  it('renders refund state in dark theme', () => {
    const { toJSON } = renderWithTheme(
      <ReceiptScreen receipt={mockReceiptRefund} />,
      'dark'
    );
    expect(toJSON()).toMatchSnapshot('receipt-refund-dark');
  });
});