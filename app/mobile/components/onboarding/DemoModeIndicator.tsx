import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';

interface DemoModeIndicatorProps {
  visible: boolean;
  compact?: boolean;
}

export default function DemoModeIndicator({ visible, compact = false }: DemoModeIndicatorProps) {
  if (!visible) return null;

  if (compact) {
    return (
      <View style={styles.compactContainer}>
        <Ionicons name="school-outline" size={16} color="#2563EB" />
        <Text style={styles.compactText}>DEMO</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Ionicons name="school-outline" size={20} color="#2563EB" />
      <Text style={styles.text}>Demo Mode - Practice with testnet funds</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#EFF6FF',
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#BFDBFE',
    marginVertical: 8,
  },
  compactContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#EFF6FF',
    paddingVertical: 4,
    paddingHorizontal: 8,
    borderRadius: 4,
    borderWidth: 1,
    borderColor: '#BFDBFE',
  },
  text: {
    color: '#1E40AF',
    fontSize: 14,
    fontWeight: '600',
    marginLeft: 8,
    flex: 1,
  },
  compactText: {
    color: '#1E40AF',
    fontSize: 12,
    fontWeight: '700',
    marginLeft: 4,
  },
});
