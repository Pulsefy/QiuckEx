import React, { useState } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  LayoutAnimation,
  Platform,
  UIManager,
} from 'react-native';
import { useTheme } from '../../hooks/useTheme';
import { useClipboard } from '../../hooks/useClipboard';
import { ContractMetadata } from './ContractMetadata';
import { NetworkBadge } from './NetworkBadge';
import type { ReceiptMetadata, ContractMetadata as ContractType, NetworkMetadata } from '../../types/receipt';

// Enable LayoutAnimation on Android
if (Platform.OS === 'android' && UIManager.setLayoutAnimationEnabledExperimental) {
  UIManager.setLayoutAnimationEnabledExperimental(true);
}

interface MetadataSectionProps {
  receiptMetadata: ReceiptMetadata;
  contract: ContractType;
  network: NetworkMetadata;
}

function truncateHash(hash: string): string {
  if (hash.length <= 16) return hash;
  return `${hash.slice(0, 8)}...${hash.slice(-8)}`;
}

export function MetadataSection({ receiptMetadata, contract, network }: MetadataSectionProps) {
  const [expanded, setExpanded] = useState(false);
  const { color, tokens } = useTheme();
  const { copied, copy } = useClipboard();

  const toggleExpand = () => {
    LayoutAnimation.configureNext(LayoutAnimation.Presets.easeInEaseOut);
    setExpanded(!expanded);
  };

  const styles = themedStyles({ color, tokens, expanded });

  return (
    <View style={styles.container}>
      {/* Header — always visible */}
      <TouchableOpacity
        style={styles.header}
        onPress={toggleExpand}
        activeOpacity={0.8}
      >
        <Text style={styles.headerTitle}>Transaction Details</Text>
        <Text style={styles.chevron}>{expanded ? '▼' : '▶'}</Text>
      </TouchableOpacity>

      {/* Always-visible summary */}
      <View style={styles.summary}>
        <View style={styles.hashRow}>
          <Text style={styles.hashLabel}>Receipt Hash</Text>
          <View style={styles.hashValueRow}>
            <Text style={styles.hashValue}>{truncateHash(receiptMetadata.receiptHash)}</Text>
            <TouchableOpacity
              onPress={() => copy(receiptMetadata.receiptHash, 'Receipt hash')}
              style={styles.copyButton}
            >
              <Text>{copied ? '✓' : '📋'}</Text>
            </TouchableOpacity>
          </View>
        </View>

        <NetworkBadge network={network.network} ledger={network.ledger} />

        <View style={styles.timestampRow}>
          <Text style={styles.timestampLabel}>Created</Text>
          <Text style={styles.timestampValue}>{receiptMetadata.createdAt}</Text>
        </View>
      </View>

      {/* Expandable details */}
      {expanded && (
        <View style={styles.details}>
          <View style={styles.divider} />
          
          <ContractMetadata contract={contract} />
          
          <View style={styles.divider} />
          
          <View style={styles.networkDetails}>
            <Text style={styles.sectionTitle}>Network</Text>
            <DetailRow label="Horizon URL" value={network.horizonUrl} />
            <DetailRow label="Ledger Close" value={network.ledgerCloseTime} />
            <DetailRow label="Passphrase" value={contract.networkPassphrase} truncate />
          </View>

          {receiptMetadata.expiresAt && (
            <>
              <View style={styles.divider} />
              <View style={styles.expiryRow}>
                <Text style={styles.expiryLabel}>⏰ Expires</Text>
                <Text style={styles.expiryValue}>{receiptMetadata.expiresAt}</Text>
              </View>
            </>
          )}
        </View>
      )}
    </View>
  );
}

function DetailRow({ label, value, truncate }: { label: string; value: string; truncate?: boolean }) {
  const { color, tokens } = useTheme();
  
  return (
    <View style={detailStyles.row}>
      <Text style={[detailStyles.label, { color: color(tokens.textMuted) }]}>{label}</Text>
      <Text
        style={[detailStyles.value, { color: color(tokens.textPrimary) }]}
        numberOfLines={1}
        ellipsizeMode={truncate ? 'middle' : undefined}
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
    paddingVertical: 8,
  },
  label: {
    fontSize: 13,
    fontWeight: '500',
  },
  value: {
    fontSize: 13,
    fontWeight: '600',
    maxWidth: '60%',
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
  },
});

function themedStyles({ color, tokens, expanded }: any) {
  return StyleSheet.create({
    container: {
      backgroundColor: color(tokens.surfaceElevated),
      borderRadius: 16,
      borderWidth: 1,
      borderColor: color(tokens.border),
      overflow: 'hidden',
    },
    header: {
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'space-between',
      paddingHorizontal: 16,
      paddingVertical: 14,
      backgroundColor: color(tokens.surface),
    },
    headerTitle: {
      fontSize: 16,
      fontWeight: '700',
      color: color(tokens.textPrimary),
    },
    chevron: {
      fontSize: 12,
      color: color(tokens.textMuted),
    },
    summary: {
      padding: 16,
      gap: 12,
    },
    hashRow: {
      gap: 4,
    },
    hashLabel: {
      fontSize: 12,
      color: color(tokens.textMuted),
      textTransform: 'uppercase',
      letterSpacing: 0.5,
    },
    hashValueRow: {
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'space-between',
    },
    hashValue: {
      fontSize: 15,
      fontWeight: '700',
      color: color(tokens.textPrimary),
      fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    },
    copyButton: {
      padding: 6,
      borderRadius: 6,
      backgroundColor: color(tokens.surface),
    },
    timestampRow: {
      flexDirection: 'row',
      justifyContent: 'space-between',
      alignItems: 'center',
    },
    timestampLabel: {
      fontSize: 13,
      color: color(tokens.textMuted),
    },
    timestampValue: {
      fontSize: 13,
      color: color(tokens.textSecondary),
      fontWeight: '500',
    },
    divider: {
      height: 1,
      backgroundColor: color(tokens.border),
      marginHorizontal: 16,
    },
    details: {
      padding: 16,
      paddingTop: 0,
      gap: 16,
    },
    sectionTitle: {
      fontSize: 13,
      fontWeight: '700',
      color: color(tokens.textMuted),
      textTransform: 'uppercase',
      letterSpacing: 0.5,
      marginBottom: 4,
    },
    networkDetails: {
      gap: 4,
    },
    expiryRow: {
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'space-between',
      paddingVertical: 8,
      backgroundColor: color(tokens.state.highlight),
      marginHorizontal: -16,
      paddingHorizontal: 16,
      marginBottom: -16,
    },
    expiryLabel: {
      fontSize: 13,
      fontWeight: '600',
      color: color(tokens.status.warning),
    },
    expiryValue: {
      fontSize: 13,
      fontWeight: '600',
      color: color(tokens.textPrimary),
    },
  });
}