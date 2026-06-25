import React from 'react';
import { View, Text, StyleSheet, ScrollView } from 'react-native';
import QRCode from 'react-native-qrcode-svg';
import { useTheme } from '../hooks/useTheme';
import { themeTokens } from '../theme/tokens';

type ReceiptStatus = 'success' | 'pending' | 'failed';

interface ReceiptData {
  id: string;
  amount: string;
  asset: string;
  sender: string;
  timestamp: string;
  status: ReceiptStatus;
  memo?: string;
}

export function ReceiptScreen({ receipt }: { receipt: ReceiptData }) {
  const { color, isDark, tokens } = useTheme();

  const styles = themedStyles({ color, isDark, tokens });

  const statusConfig = {
    success: {
      label: 'Completed',
      color: tokens.semantic.success,
      bgColor: tokens.state.highlight,
    },
    pending: {
      label: 'Processing',
      color: tokens.semantic.pending,
      bgColor: tokens.surfaceOverlay,
    },
    failed: {
      label: 'Failed',
      color: tokens.semantic.error,
      bgColor: tokens.state.error,
    },
  };

  const status = statusConfig[receipt.status];

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Status Badge */}
      <View
        style={[
          styles.statusBadge,
          { backgroundColor: color(status.bgColor) },
        ]}
      >
        <View
          style={[
            styles.statusDot,
            { backgroundColor: color(status.color) },
          ]}
        />
        <Text style={[styles.statusText, { color: color(status.color) }]}>
          {status.label}
        </Text>
      </View>

      {/* Amount Display */}
      <View style={styles.amountSection}>
        <Text style={styles.amountLabel}>You received</Text>
        <Text style={styles.amountValue}>
          {receipt.amount} {receipt.asset}
        </Text>
      </View>

      {/* QR Code */}
      <View style={styles.qrContainer}>
        <View style={styles.qrWrapper}>
          <QRCode
            value={`quickex.to/receipt/${receipt.id}`}
            size={180}
            color={color(tokens.text.primary)}
            backgroundColor={color(tokens.surface)}
          />
        </View>
        <Text style={styles.qrLabel}>Scan to verify on Stellar</Text>
      </View>

      {/* Transaction Details */}
      <View style={styles.detailsCard}>
        <DetailRow label="Transaction ID" value={receipt.id} />
        <DetailRow label="From" value={receipt.sender} />
        <DetailRow label="Time" value={receipt.timestamp} />
        {receipt.memo && (
          <DetailRow label="Memo" value={receipt.memo} />
        )}
      </View>

      {/* Security Note */}
      <View style={styles.securityNote}>
        <Text style={styles.securityIcon}>🔒</Text>
        <Text style={styles.securityText}>
          Secured by Stellar blockchain. Immutable and verifiable.
        </Text>
      </View>
    </ScrollView>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  const { color, tokens } = useTheme();
  
  return (
    <View style={detailStyles.row}>
      <Text style={[detailStyles.label, { color: color(tokens.text.secondary) }]}>
        {label}
      </Text>
      <Text
        style={[detailStyles.value, { color: color(tokens.text.primary) }]}
        numberOfLines={1}
        ellipsizeMode="middle"
      >
        {value}
      </Text>
    </View>
  );
}

const detailStyles = StyleSheet.create({
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
    borderBottomWidth: 1,
  },
  label: {
    fontSize: 14,
    fontWeight: '500',
  },
  value: {
    fontSize: 14,
    fontWeight: '600',
    maxWidth: '60%',
  },
});

function themedStyles({ color, isDark, tokens }: {
  color: (t: any) => string;
  isDark: boolean;
  tokens: typeof themeTokens;
}) {
  return StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: color(tokens.surface),
    },
    content: {
      padding: 20,
      alignItems: 'center',
    },
    statusBadge: {
      flexDirection: 'row',
      alignItems: 'center',
      paddingHorizontal: 16,
      paddingVertical: 8,
      borderRadius: 20,
      marginBottom: 24,
    },
    statusDot: {
      width: 8,
      height: 8,
      borderRadius: 4,
      marginRight: 8,
    },
    statusText: {
      fontSize: 14,
      fontWeight: '700',
    },
    amountSection: {
      alignItems: 'center',
      marginBottom: 32,
    },
    amountLabel: {
      fontSize: 16,
      color: color(tokens.text.secondary),
      marginBottom: 8,
    },
    amountValue: {
      fontSize: 40,
      fontWeight: '800',
      color: color(tokens.text.primary),
    },
    qrContainer: {
      alignItems: 'center',
      marginBottom: 32,
    },
    qrWrapper: {
      padding: 20,
      borderRadius: 20,
      backgroundColor: color(tokens.surface),
      borderWidth: 2,
      borderColor: color(tokens.border.default),
      shadowColor: color(tokens.text.primary),
      shadowOffset: { width: 0, height: 2 },
      shadowOpacity: isDark ? 0.1 : 0.05,
      shadowRadius: 8,
      elevation: 2,
    },
    qrLabel: {
      marginTop: 12,
      fontSize: 13,
      color: color(tokens.text.tertiary),
    },
    detailsCard: {
      width: '100%',
      backgroundColor: color(tokens.surfaceElevated),
      borderRadius: 16,
      padding: 20,
      marginBottom: 20,
      borderWidth: 1,
      borderColor: color(tokens.border.subtle),
    },
    securityNote: {
      flexDirection: 'row',
      alignItems: 'center',
      padding: 16,
      backgroundColor: color(tokens.state.info),
      borderRadius: 12,
      width: '100%',
    },
    securityIcon: {
      fontSize: 20,
      marginRight: 12,
    },
    securityText: {
      flex: 1,
      fontSize: 13,
      color: color(tokens.text.secondary),
      lineHeight: 18,
    },
  });
}