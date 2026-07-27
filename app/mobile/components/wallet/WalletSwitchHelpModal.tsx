import React from 'react';
import { Modal, View, Text, StyleSheet, TouchableOpacity, ScrollView, SafeAreaView } from 'react-native';
import { useNetworkGuardContext } from '../../contexts/NetworkGuardContext';

/**
 * Modal that provides step-by-step instructions for switching networks in specific wallets.
 */
export const WalletSwitchHelpModal: React.FC<{ visible: boolean; onClose: () => void }> = ({
  visible,
  onClose,
}) => {
  const { guard } = useNetworkGuardContext();

  const getInstructions = () => {
    switch (guard.walletType) {
      case 'freighter':
        return [
          'Open Freighter browser extension',
          'Tap the Settings gear icon',
          'Select "Network"',
          'Choose "Test Net" from the options',
        ];
      case 'xbull':
        return [
          'Open xBull Wallet',
          'Tap the network name at the top of the screen',
          'Select "Stellar Testnet"',
        ];
      case 'albedo':
        return [
          'Open Albedo in your browser or app',
          'Go to "Settings"',
          'Switch "Network" to "Testnet"',
        ];
      case 'lobstr':
        return [
          'Open LOBSTR app',
          'Go to "Settings" > "Advanced"',
          'Enable "Testnet Mode"',
        ];
      default:
        return [
          'Open your Stellar wallet',
          'Go to settings or network preferences',
          'Switch the network from Public/Mainnet to Testnet',
        ];
    }
  };

  return (
    <Modal visible={visible} animationType="slide" transparent>
      <View style={styles.overlay}>
        <SafeAreaView style={styles.content}>
          <View style={styles.header}>
            <Text style={styles.title}>Network Switch Guide</Text>
            <TouchableOpacity onPress={onClose} style={styles.closeHitbox}>
              <Text style={styles.closeIcon}>✕</Text>
            </TouchableOpacity>
          </View>

          <ScrollView contentContainerStyle={styles.body}>
            <View style={styles.mismatchNotice}>
              <Text style={styles.noticeLabel}>Mismatch Detected</Text>
              <Text style={styles.noticeText}>
                Your wallet is on {guard.currentNetwork.toUpperCase()} but this action requires{' '}
                {guard.expectedNetwork.toUpperCase()}.
              </Text>
            </View>

            <Text style={styles.walletHeader}>Instructions for {guard.walletType || 'your wallet'}:</Text>
            {getInstructions().map((step, i) => (
              <View key={i} style={styles.step}>
                <View style={styles.stepNumber}><Text style={styles.stepNumberText}>{i + 1}</Text></View>
                <Text style={styles.stepText}>{step}</Text>
              </View>
            ))}
          </ScrollView>

          <TouchableOpacity style={styles.footerButton} onPress={onClose}>
            <Text style={styles.footerButtonText}>Got it</Text>
          </TouchableOpacity>
        </SafeAreaView>
      </View>
    </Modal>
  );
};

const styles = StyleSheet.create({
  overlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.6)', justifyContent: 'flex-end' },
  content: { backgroundColor: 'white', borderTopLeftRadius: 24, borderTopRightRadius: 24, maxHeight: '85%' },
  header: { flexDirection: 'row', justifyContent: 'space-between', padding: 24, borderBottomWidth: 1, borderBottomColor: '#f3f4f6' },
  title: { fontSize: 20, fontWeight: 'bold', color: '#111827' },
  closeHitbox: { padding: 4 },
  closeIcon: { fontSize: 20, color: '#9ca3af' },
  body: { padding: 24 },
  mismatchNotice: { backgroundColor: '#fee2e2', padding: 16, borderRadius: 12, marginBottom: 24 },
  noticeLabel: { color: '#991b1b', fontWeight: 'bold', fontSize: 12, textTransform: 'uppercase', marginBottom: 4 },
  noticeText: { color: '#7f1d1d', fontSize: 14, lineHeight: 20 },
  walletHeader: { fontSize: 16, fontWeight: 'bold', color: '#374151', marginBottom: 16, textTransform: 'capitalize' },
  step: { flexDirection: 'row', marginBottom: 20, alignItems: 'center' },
  stepNumber: { width: 28, height: 28, borderRadius: 14, backgroundColor: '#3b82f6', justifyContent: 'center', alignItems: 'center', marginRight: 12 },
  stepNumberText: { color: 'white', fontWeight: 'bold', fontSize: 14 },
  stepText: { fontSize: 15, color: '#4b5563', flex: 1, lineHeight: 22 },
  footerButton: { margin: 24, backgroundColor: '#111827', padding: 18, borderRadius: 16, alignItems: 'center' },
  footerButtonText: { color: 'white', fontWeight: 'bold', fontSize: 16 },
});