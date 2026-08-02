import React from 'react';
import { View, Text, StyleSheet, SafeAreaView } from 'react-native';
import { useNetworkGuardContext } from '../../contexts/NetworkGuardContext';
import { useWalletContext } from '../../hooks/useWalletContext';
import { APP_ENVIRONMENT, STELLAR_NETWORK } from '../../src/config/build';
import type { WalletErrorCode } from '../../types/wallet';

/**
 * Global banner that indicates the current environment and warns on mismatch.
 * Shows a persistent STAGING banner when the app is built in staging mode.
 * Shows a persistent testnet indicator when the app targets testnet.
 * Also surfaces stale-session and environment-mismatch warnings.
 */
export const GlobalNetworkBanner = () => {
  const { guard } = useNetworkGuardContext();
  const { wallet } = useWalletContext();

  const isStaging = APP_ENVIRONMENT === 'staging';

  // Staging banner is always visible regardless of wallet connection
  if (isStaging) {
    return (
      <SafeAreaView style={[styles.safeArea, styles.bgStaging]}>
        <View style={styles.container}>
          <Text style={[styles.text, styles.textStaging]}>
            🚧 STAGING MODE
          </Text>
          <Text style={[styles.subtext, styles.textStaging]}>
            {guard.isConnected
              ? `Connected to ${guard.currentNetwork.toUpperCase()} • Backend: staging-api.quickex.to`
              : 'Testnet backend • Not intended for production use'}
          </Text>
        </View>
      </SafeAreaView>
    );
  }

  // Show stale / environment-mismatch banner when wallet has session error
  if (
    wallet.error &&
    (wallet.error.code === 'session_expired' ||
      wallet.error.code === 'session_environment_mismatch' ||
      wallet.error.code === 'session_corrupted')
  ) {
    const sessionErrorConfig: Record<string, { title: string; subtext: string }> = {
      session_expired: {
        title: '⏰ Session Expired',
        subtext: 'Your previous session has expired. Go to wallet settings to reconnect.',
      },
      session_environment_mismatch: {
        title: '🔄 Environment Changed',
        subtext: 'The app environment has changed since your last session. Please reconnect.',
      },
      session_corrupted: {
        title: '⚠️ Session Data Issue',
        subtext: 'Your saved session data could not be restored. Please reconnect your wallet.',
      },
    };

    const cfg = sessionErrorConfig[wallet.error.code as WalletErrorCode] ?? {
      title: '⚠️ Session Issue',
      subtext: wallet.error.message,
    };

    return (
      <SafeAreaView style={[styles.safeArea, styles.bgSessionIssue]}>
        <View style={styles.container}>
          <Text style={[styles.text, styles.textSessionIssue]}>{cfg.title}</Text>
          <Text style={[styles.subtext, styles.textSessionIssue]}>{cfg.subtext}</Text>
        </View>
      </SafeAreaView>
    );
  }

  const isTestnet = STELLAR_NETWORK === 'testnet';

  // Non-intrusive environment banner: show a subtle testnet indicator
  // even when no wallet is connected, so users always know the target network.
  if (!guard.isConnected && isTestnet) {
    return (
      <SafeAreaView style={[styles.safeArea, styles.bgTestnetIdle]}>
        <View style={styles.container}>
          <Text style={[styles.text, styles.textTestnet]}>
            🌐 Stellar Testnet Mode
          </Text>
          <Text style={[styles.subtext, styles.textTestnet]}>
            Connect a wallet to get started
          </Text>
        </View>
      </SafeAreaView>
    );
  }

  // Still restoring — wait for wallet state to settle
  if (guard.isRestoring) return null;

  // Wallet connected — show status
  const isMismatch = guard.isMismatched;

  return (
    <SafeAreaView style={[styles.safeArea, isMismatch ? styles.bgError : styles.bgWarning]}>
      <View style={styles.container}>
        <Text style={[styles.text, isMismatch ? styles.textError : styles.textWarning]}>
          {isMismatch ? '⚠️ NETWORK MISMATCH' : '🌐 Stellar Testnet Mode'}
        </Text>
        <Text style={[styles.subtext, isMismatch ? styles.textError : styles.textWarning]}>
          {isMismatch
            ? `Wallet on ${guard.currentNetwork.toUpperCase()} • App expects ${guard.expectedNetwork.toUpperCase()}`
            : `Connected to ${guard.currentNetwork.toUpperCase()}`}
        </Text>
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  safeArea: {
    width: '100%',
  },
  container: {
    paddingVertical: 8,
    paddingHorizontal: 16,
    alignItems: 'center',
    justifyContent: 'center',
  },
  bgWarning: {
    backgroundColor: '#FFFBEB', // amber-50
    borderBottomWidth: 1,
    borderBottomColor: '#FCD34D',
  },
  bgError: {
    backgroundColor: '#FEE2E2', // red-100
    borderBottomWidth: 1,
    borderBottomColor: '#EF4444',
  },
  bgStaging: {
    backgroundColor: '#F3E8FF', // purple-100
    borderBottomWidth: 2,
    borderBottomColor: '#A855F7', // purple-500
  },
  bgTestnetIdle: {
    backgroundColor: '#F0FDF4', // green-50
    borderBottomWidth: 1,
    borderBottomColor: '#86EFAC', // green-300
  },
  bgSessionIssue: {
    backgroundColor: '#FFF7ED', // orange-50
    borderBottomWidth: 1,
    borderBottomColor: '#F97316', // orange-500
  },
  text: { fontSize: 14, fontWeight: 'bold' },
  subtext: { fontSize: 11, marginTop: 2 },
  textWarning: { color: '#92400E' },
  textError: { color: '#7F1D1D' },
  textStaging: { color: '#6B21A8' }, // purple-800
  textSessionIssue: { color: '#9A3412' }, // orange-800
  textTestnet: { color: '#166534' }, // green-800
});