import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { useTheme } from '../../hooks/useTheme';

interface NetworkBadgeProps {
  network: 'mainnet' | 'testnet' | 'futurenet';
  ledger?: number;
}

const NETWORK_CONFIG = {
  mainnet: {
    label: 'Mainnet',
    dotColor: '#10B981', // green
    bgColor: '#ECFDF5',
  },
  testnet: {
    label: 'Testnet',
    dotColor: '#F59E0B', // amber
    bgColor: '#FFF3E5',
  },
  futurenet: {
    label: 'Futurenet',
    dotColor: '#8B5CF6', // purple
    bgColor: '#F3E8FF',
  },
};

export function NetworkBadge({ network, ledger }: NetworkBadgeProps) {
  const { color, tokens } = useTheme();
  const config = NETWORK_CONFIG[network];

  const styles = themedStyles({ color, tokens, config });

  return (
    <View style={styles.container}>
      <View style={styles.dot} />
      <Text style={styles.label}>{config.label}</Text>
      {ledger !== undefined && (
        <Text style={styles.ledger}>· Ledger {ledger.toLocaleString()}</Text>
      )}
    </View>
  );
}

function themedStyles({ color, tokens, config }: any) {
  return StyleSheet.create({
    container: {
      flexDirection: 'row',
      alignItems: 'center',
      paddingHorizontal: 10,
      paddingVertical: 6,
      borderRadius: 20,
      backgroundColor: config.bgColor,
      alignSelf: 'flex-start',
    },
    dot: {
      width: 8,
      height: 8,
      borderRadius: 4,
      backgroundColor: config.dotColor,
      marginRight: 6,
    },
    label: {
      fontSize: 13,
      fontWeight: '700',
      color: config.dotColor,
    },
    ledger: {
      fontSize: 12,
      color: color(tokens.textMuted),
      marginLeft: 6,
    },
  });
}