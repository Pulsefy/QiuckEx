import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { useTheme } from '../../hooks/useTheme';
import { TimelineNode } from './TimelineNode';
import type { TimelineEvent } from '../../types/receipt';

interface StatusTimelineProps {
  events: TimelineEvent[];
  status: 'pending' | 'success' | 'failed' | 'refund';
}

const STATUS_CONFIG = {
  pending: {
    title: 'Payment Pending',
    subtitle: 'Your transaction is being processed on the Stellar network.',
    icon: '⏳',
    color: '#F59E0B',
  },
  success: {
    title: 'Payment Successful',
    subtitle: 'Funds have been settled to the recipient wallet.',
    icon: '✅',
    color: '#10B981',
  },
  failed: {
    title: 'Payment Failed',
    subtitle: 'The transaction could not be completed. No funds were deducted.',
    icon: '❌',
    color: '#EF4444',
  },
  refund: {
    title: 'Payment Refunded',
    subtitle: 'Funds have been returned to your wallet.',
    icon: '↩️',
    color: '#8B5CF6',
  },
};

export function StatusTimeline({ events, status }: StatusTimelineProps) {
  const { color, tokens } = useTheme();
  const config = STATUS_CONFIG[status];

  const styles = themedStyles({ color, tokens, config });

  return (
    <View style={styles.container}>
      {/* Status Header */}
      <View style={styles.header}>
        <View style={[styles.statusIcon, { backgroundColor: `${config.color}20` }]}>
          <Text style={styles.statusIconText}>{config.icon}</Text>
        </View>
        <View style={styles.statusText}>
          <Text style={styles.statusTitle}>{config.title}</Text>
          <Text style={styles.statusSubtitle}>{config.subtitle}</Text>
        </View>
      </View>

      {/* Timeline */}
      <View style={styles.timeline}>
        <Text style={styles.timelineTitle}>Transaction Timeline</Text>
        {events.map((event, index) => (
          <TimelineNode
            key={event.id}
            event={event}
            isLast={index === events.length - 1}
          />
        ))}
      </View>

      {/* Support hint */}
      <View style={styles.supportHint}>
        <Text style={styles.supportIcon}>💡</Text>
        <Text style={styles.supportText}>
          Having issues? Copy the receipt details below for support.
        </Text>
      </View>
    </View>
  );
}

function themedStyles({ color, tokens, config }: any) {
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
      padding: 20,
      backgroundColor: color(tokens.surface),
      borderBottomWidth: 1,
      borderBottomColor: color(tokens.border),
    },
    statusIcon: {
      width: 48,
      height: 48,
      borderRadius: 24,
      alignItems: 'center',
      justifyContent: 'center',
      marginRight: 16,
    },
    statusIconText: {
      fontSize: 24,
    },
    statusText: {
      flex: 1,
    },
    statusTitle: {
      fontSize: 18,
      fontWeight: '800',
      color: config.color,
      marginBottom: 4,
    },
    statusSubtitle: {
      fontSize: 14,
      color: color(tokens.textSecondary),
      lineHeight: 20,
    },
    timeline: {
      padding: 20,
      paddingTop: 16,
    },
    timelineTitle: {
      fontSize: 13,
      fontWeight: '700',
      color: color(tokens.textMuted),
      textTransform: 'uppercase',
      letterSpacing: 0.5,
      marginBottom: 16,
    },
    supportHint: {
      flexDirection: 'row',
      alignItems: 'center',
      padding: 16,
      backgroundColor: `${config.color}10`,
      marginHorizontal: 16,
      marginBottom: 16,
      borderRadius: 12,
    },
    supportIcon: {
      fontSize: 16,
      marginRight: 10,
    },
    supportText: {
      flex: 1,
      fontSize: 13,
      color: color(tokens.textSecondary),
      lineHeight: 18,
    },
  });
}