import * as Linking from 'expo-linking';
import { useLocalSearchParams, useRouter } from 'expo-router';
import React from 'react';
import {
  Alert,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

export default function PaymentConfirmationScreen() {
  const router = useRouter();
  const params = useLocalSearchParams<{
    username: string;
    amount: string;
    asset: string;
    memo?: string;
    privacy?: string;
  }>();

  const { username, amount, asset, memo, privacy } = params;
  const isPrivate = privacy === 'true';
  const isValid = username && amount && asset;

  const handlePayWithWallet = async () => {
    const stellarUri = `web+stellar:pay?destination=${username}&amount=${amount}&asset_code=${asset}${memo ? `&memo=${encodeURIComponent(memo)}` : ''}`;
    const canOpen = await Linking.canOpenURL(stellarUri);
    if (canOpen) {
      await Linking.openURL(stellarUri);
    } else {
      Alert.alert(
        'No Wallet Found',
        'Install a Stellar-compatible wallet to complete this payment.',
        [{ text: 'OK' }],
      );
    }
  };

  if (!isValid) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.content}>
          <View style={styles.errorCard}>
            <Text style={styles.errorIcon}>!</Text>
            <Text style={styles.errorTitle}>Invalid Payment Link</Text>
            <Text style={styles.errorBody}>
              This payment link is missing required information. Please try scanning again or check the link.
            </Text>
          </View>
          <Pressable style={styles.secondaryBtn} onPress={() => router.replace('/')}>
            <Text style={styles.secondaryBtnText}>Go Back</Text>
          </Pressable>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.heading}>Confirm Payment</Text>
        <Text style={styles.subheading}>Review the details below before paying</Text>

        <View style={styles.card}>
          <Row label="Recipient" value={`@${username}`} />
          <View style={styles.divider} />
          <Row label="Amount" value={`${amount} ${asset}`} highlight />
          {memo ? (
            <>
              <View style={styles.divider} />
              <Row label="Memo" value={memo} />
            </>
          ) : null}
          {isPrivate ? (
            <>
              <View style={styles.divider} />
              <Row label="Privacy" value="X-Ray enabled" />
            </>
          ) : null}
        </View>

        <View style={styles.actions}>
          <Pressable style={styles.primaryBtn} onPress={handlePayWithWallet}>
            <Text style={styles.primaryBtnText}>Pay with Wallet</Text>
          </Pressable>
          <Pressable style={styles.secondaryBtn} onPress={() => router.replace('/')}>
            <Text style={styles.secondaryBtnText}>Cancel</Text>
          </Pressable>
        </View>
      </View>
    </SafeAreaView>
  );
}

function Row({
  label,
  value,
  highlight,
}: {
  label: string;
  value: string;
  highlight?: boolean;
}) {
  return (
    <View style={styles.row}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={[styles.rowValue, highlight && styles.rowValueHighlight]}>
        {value}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#fff' },
  content: {
    flex: 1,
    padding: 24,
    justifyContent: 'center',
  },
  heading: {
    fontSize: 32,
    fontWeight: 'bold',
    color: '#000',
    marginBottom: 4,
  },
  subheading: {
    fontSize: 16,
    color: '#888',
    marginBottom: 32,
  },
  card: {
    backgroundColor: '#F5F5F5',
    borderRadius: 16,
    padding: 20,
    marginBottom: 40,
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 14,
  },
  rowLabel: { fontSize: 15, color: '#888' },
  rowValue: { fontSize: 16, fontWeight: '500', color: '#222', flexShrink: 1, textAlign: 'right' },
  rowValueHighlight: { fontSize: 20, fontWeight: '700', color: '#000' },
  divider: { height: 1, backgroundColor: '#E5E5E5' },
  actions: { gap: 12 },
  primaryBtn: {
    backgroundColor: '#000',
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: 'center',
  },
  primaryBtnText: { color: '#fff', fontSize: 18, fontWeight: '700' },
  secondaryBtn: {
    paddingVertical: 14,
    alignItems: 'center',
  },
  secondaryBtnText: { color: '#888', fontSize: 16, fontWeight: '500' },
  errorCard: {
    backgroundColor: '#FFF3F3',
    borderRadius: 16,
    padding: 32,
    alignItems: 'center',
    marginBottom: 24,
  },
  errorIcon: {
    fontSize: 36,
    fontWeight: 'bold',
    color: '#FF3B30',
    backgroundColor: '#FFE5E5',
    width: 56,
    height: 56,
    lineHeight: 56,
    borderRadius: 28,
    textAlign: 'center',
    marginBottom: 16,
    overflow: 'hidden',
  },
  errorTitle: { fontSize: 22, fontWeight: '700', color: '#222', marginBottom: 8 },
  errorBody: { fontSize: 15, color: '#888', textAlign: 'center', lineHeight: 22 },
});
