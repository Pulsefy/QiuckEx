import React from 'react';
import { render, waitFor } from '@testing-library/react-native';
import { Appearance } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { ThemeProvider } from '../src/context/ThemeContext';
import { PaymentScreen } from '../src/screens/PaymentScreen';
import { ReceiptScreen } from '../src/screens/ReceiptScreen';
import { SettingsScreen } from '../src/screens/SettingsScreen';
import { NotificationScreen } from '../src/screens/NotificationScreen';
import { mockReceiptSuccess } from './fixtures/mockReceipt';

async function renderWithTheme(component: React.ReactElement, mode: 'light' | 'dark' | 'system', systemAppearance: 'light' | 'dark' = 'light') {
  jest.spyOn(Appearance, 'getColorScheme').mockReturnValue(systemAppearance);
  
  if (mode === 'system') {
    await AsyncStorage.removeItem('@quickex_theme_mode');
  } else {
    await AsyncStorage.setItem('@quickex_theme_mode', mode);
  }

  const utils = render(
    <ThemeProvider>{component}</ThemeProvider>
  );

  // ThemeProvider renders null until it reads from AsyncStorage. 
  // We wait for it to render actual content.
  await waitFor(() => {
    expect(utils.toJSON()).not.toBeNull();
  });

  return utils;
}

describe('Theme Consistency Screenshots', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // PaymentScreen
  it('PaymentScreen renders correctly in light theme', async () => {
    const { toJSON } = await renderWithTheme(<PaymentScreen />, 'light');
    expect(toJSON()).toMatchSnapshot('payment-light');
  });

  it('PaymentScreen renders correctly in dark theme', async () => {
    const { toJSON } = await renderWithTheme(<PaymentScreen />, 'dark');
    expect(toJSON()).toMatchSnapshot('payment-dark');
  });

  it('PaymentScreen renders correctly in system-light theme', async () => {
    const { toJSON } = await renderWithTheme(<PaymentScreen />, 'system', 'light');
    expect(toJSON()).toMatchSnapshot('payment-system-light');
  });

  it('PaymentScreen renders correctly in system-dark theme', async () => {
    const { toJSON } = await renderWithTheme(<PaymentScreen />, 'system', 'dark');
    expect(toJSON()).toMatchSnapshot('payment-system-dark');
  });

  // ReceiptScreen
  it('ReceiptScreen renders correctly in light theme', async () => {
    const { toJSON } = await renderWithTheme(<ReceiptScreen receipt={mockReceiptSuccess} />, 'light');
    expect(toJSON()).toMatchSnapshot('receipt-light');
  });

  it('ReceiptScreen renders correctly in dark theme', async () => {
    const { toJSON } = await renderWithTheme(<ReceiptScreen receipt={mockReceiptSuccess} />, 'dark');
    expect(toJSON()).toMatchSnapshot('receipt-dark');
  });

  it('ReceiptScreen renders correctly in system-light theme', async () => {
    const { toJSON } = await renderWithTheme(<ReceiptScreen receipt={mockReceiptSuccess} />, 'system', 'light');
    expect(toJSON()).toMatchSnapshot('receipt-system-light');
  });

  it('ReceiptScreen renders correctly in system-dark theme', async () => {
    const { toJSON } = await renderWithTheme(<ReceiptScreen receipt={mockReceiptSuccess} />, 'system', 'dark');
    expect(toJSON()).toMatchSnapshot('receipt-system-dark');
  });

  // SettingsScreen
  it('SettingsScreen renders correctly in light theme', async () => {
    const { toJSON } = await renderWithTheme(<SettingsScreen />, 'light');
    expect(toJSON()).toMatchSnapshot('settings-light');
  });

  it('SettingsScreen renders correctly in dark theme', async () => {
    const { toJSON } = await renderWithTheme(<SettingsScreen />, 'dark');
    expect(toJSON()).toMatchSnapshot('settings-dark');
  });

  it('SettingsScreen renders correctly in system-light theme', async () => {
    const { toJSON } = await renderWithTheme(<SettingsScreen />, 'system', 'light');
    expect(toJSON()).toMatchSnapshot('settings-system-light');
  });

  it('SettingsScreen renders correctly in system-dark theme', async () => {
    const { toJSON } = await renderWithTheme(<SettingsScreen />, 'system', 'dark');
    expect(toJSON()).toMatchSnapshot('settings-system-dark');
  });

  // NotificationScreen
  it('NotificationScreen renders correctly in light theme', async () => {
    const { toJSON } = await renderWithTheme(<NotificationScreen />, 'light');
    expect(toJSON()).toMatchSnapshot('notification-light');
  });

  it('NotificationScreen renders correctly in dark theme', async () => {
    const { toJSON } = await renderWithTheme(<NotificationScreen />, 'dark');
    expect(toJSON()).toMatchSnapshot('notification-dark');
  });

  it('NotificationScreen renders correctly in system-light theme', async () => {
    const { toJSON } = await renderWithTheme(<NotificationScreen />, 'system', 'light');
    expect(toJSON()).toMatchSnapshot('notification-system-light');
  });

  it('NotificationScreen renders correctly in system-dark theme', async () => {
    const { toJSON } = await renderWithTheme(<NotificationScreen />, 'system', 'dark');
    expect(toJSON()).toMatchSnapshot('notification-system-dark');
  });
});