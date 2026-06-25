import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';
import { useTheme } from '../../hooks/useTheme';
import { useClipboard } from '../../hooks/useClipboard';
import type { ContractMetadata as ContractMetadataType } from '../../types/receipt';

interface ContractMetadataProps {
  contract: ContractMetadataType;
}

function truncateHash(hash: string, start: number = 6, end: number = 6): string {
  if (hash.length <= start + end + 3) return hash;
  return `${hash.slice(0, start)}...${hash.slice(-end)}`;
}

export function ContractMetadata({ contract }: ContractMetadataProps) {
  const { color, tokens } = useTheme();
  const { copied, copy } = useClipboard();

  const styles = themedStyles({ color, tokens });

  const handleCopy = (text: string, label: string) => {
    copy(text, label);
  };

  return (
    <View style={styles.container}>
      <Text style={styles.sectionTitle}>Contract</Text>
      
      <View style={styles.row}>
        <View style={styles.labelValue}>
          <Text style={styles.label}>Contract ID</Text>
          <Text style={styles.value}>{truncateHash(contract.contractId)}</Text>
        </View>
        <TouchableOpacity
          style={styles.copyButton}
          onPress={() => handleCopy(contract.contractId, 'Contract ID')}
          activeOpacity={0.7}
        >
          <Text style={styles.copyText}>
            {copied ? '✓' : '📋'}
          </Text>
        </TouchableOpacity>
      </View>

      <View style={styles.divider} />

      <View style={styles.row}>
        <View style={styles.labelValue}>
          <Text style={styles.label}>WASM Hash</Text>
          <Text style={styles.value}>{truncateHash(contract.wasmHash)}</Text>
        </View>
        <TouchableOpacity
          style={styles.copyButton}
          onPress={() => handleCopy(contract.wasmHash, 'WASM Hash')}
          activeOpacity={0.7}
        >
          <Text style={styles.copyText}>📋</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.divider} />

      <View style={styles.row}>
        <View style={styles.labelValue}>
          <Text style={styles.label}>Deployed</Text>
          <Text style={styles.value}>{contract.deployedAt}</Text>
        </View>
      </View>
    </View>
  );
}

function themedStyles({ color, tokens }: any) {
  return StyleSheet.create({
    container: {
      gap: 12,
    },
    sectionTitle: {
      fontSize: 13,
      fontWeight: '700',
      color: color(tokens.textMuted),
      textTransform: 'uppercase',
      letterSpacing: 0.5,
      marginBottom: 4,
    },
    row: {
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'space-between',
    },
    labelValue: {
      flex: 1,
    },
    label: {
      fontSize: 12,
      color: color(tokens.textMuted),
      marginBottom: 2,
    },
    value: {
      fontSize: 14,
      fontWeight: '600',
      color: color(tokens.textPrimary),
      fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    },
    copyButton: {
      padding: 8,
      borderRadius: 8,
      backgroundColor: color(tokens.surfaceElevated),
    },
    copyText: {
      fontSize: 16,
    },
    divider: {
      height: 1,
      backgroundColor: color(tokens.border),
    },
  });
}