import React from 'react';
import { render, screen, waitFor } from '@testing-library/react-native';
import { ThemeProvider } from '../src/context/ThemeContext';
import { ReceiptScreen } from '../src/screens/ReceiptScreen';
import {
  mockReceiptPending,
  mockReceiptSuccess,
  mockReceiptFailed,
  mockReceiptRefund,
} from './fixtures/mockReceipt';

function renderWithTheme(component: React.ReactElement, mode: 'light' | 'dark' = 'light') {
  jest.spyOn(require('react-native').Appearance, 'getColorScheme').mockReturnValue(mode);
  return render(<ThemeProvider>{component}</ThemeProvider>);
}

describe('ReceiptScreen v3 Screenshots', () => {
  it('renders pending state in light theme', async () => {
    renderWithTheme(
      <ReceiptScreen receipt={mockReceiptPending} />,
      'light'
    );
    await waitFor(() => expect(screen.toJSON()).toBeTruthy());
    expect(screen.toJSON()).toMatchSnapshot('receipt-pending-light');
  });

  it('renders pending state in dark theme', async () => {
    renderWithTheme(
      <ReceiptScreen receipt={mockReceiptPending} />,
      'dark'
    );
    await waitFor(() => expect(screen.toJSON()).toBeTruthy());
    expect(screen.toJSON()).toMatchSnapshot('receipt-pending-dark');
  });

  it('renders success state in light theme', async () => {
    renderWithTheme(
      <ReceiptScreen receipt={mockReceiptSuccess} />,
      'light'
    );
    await waitFor(() => expect(screen.toJSON()).toBeTruthy());
    expect(screen.toJSON()).toMatchSnapshot('receipt-success-light');
  });

  it('renders success state in dark theme', async () => {
    renderWithTheme(
      <ReceiptScreen receipt={mockReceiptSuccess} />,
      'dark'
    );
    await waitFor(() => expect(screen.toJSON()).toBeTruthy());
    expect(screen.toJSON()).toMatchSnapshot('receipt-success-dark');
  });

  it('renders failed state in light theme', async () => {
    renderWithTheme(
      <ReceiptScreen receipt={mockReceiptFailed} />,
      'light'
    );
    await waitFor(() => expect(screen.toJSON()).toBeTruthy());
    expect(screen.toJSON()).toMatchSnapshot('receipt-failed-light');
  });

  it('renders failed state in dark theme', async () => {
    renderWithTheme(
      <ReceiptScreen receipt={mockReceiptFailed} />,
      'dark'
    );
    await waitFor(() => expect(screen.toJSON()).toBeTruthy());
    expect(screen.toJSON()).toMatchSnapshot('receipt-failed-dark');
  });

  it('renders refund state in light theme', async () => {
    renderWithTheme(
      <ReceiptScreen receipt={mockReceiptRefund} />,
      'light'
    );
    await waitFor(() => expect(screen.toJSON()).toBeTruthy());
    expect(screen.toJSON()).toMatchSnapshot('receipt-refund-light');
  });

  it('renders refund state in dark theme', async () => {
    renderWithTheme(
      <ReceiptScreen receipt={mockReceiptRefund} />,
      'dark'
    );
    await waitFor(() => expect(screen.toJSON()).toBeTruthy());
    expect(screen.toJSON()).toMatchSnapshot('receipt-refund-dark');
  });
});