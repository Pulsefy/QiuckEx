import React from 'react';
import { View, Text, StyleSheet, SafeAreaView } from 'react-native';
import { useNetworkGuardContext } from '../../contexts/NetworkGuardContext';

/**
 * Global banner that indicates the current environment and warns on mismatch.
 */
export const GlobalNetworkBanner = () => {
  const { guard } = useNetworkGuardContext();

  // Don't show anything if not connected or still initializing
  if (!guard.isConnected || guard.isRestoring) return null;

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
  text: { fontSize: 14, fontWeight: 'bold' },
  subtext: { fontSize: 11, marginTop: 2 },
  textWarning: { color: '#92400E' },
  textError: { color: '#7F1D1D' },
});