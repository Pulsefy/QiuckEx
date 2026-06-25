import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { useTheme } from '../../hooks/useTheme';
import type { TimelineEvent } from '../../types/receipt';

interface TimelineNodeProps {
  event: TimelineEvent;
  isLast: boolean;
}

const STEP_ICONS: Record<string, string> = {
  created: '📝',
  submitted: '📤',
  validated: '✅',
  executed: '⚡',
  settled: '💰',
  refunded: '↩️',
};

const STEP_EMOJI: Record<TimelineEvent['status'], string> = {
  completed: '✓',
  current: '⏳',
  upcoming: '○',
  failed: '✕',
};

const STEP_COLORS = {
  completed: { bg: '#10B981', text: '#FFFFFF' },
  current: { bg: '#F59E0B', text: '#FFFFFF' },
  upcoming: { bg: '#E5E7EB', text: '#9CA3AF' },
  failed: { bg: '#EF4444', text: '#FFFFFF' },
};

export function TimelineNode({ event, isLast }: TimelineNodeProps) {
  const { color, tokens } = useTheme();
  const stepColor = STEP_COLORS[event.status];

  const styles = themedStyles({ color, tokens, stepColor, isLast, event });

  return (
    <View style={styles.container}>
      {/* Connector line */}
      {!isLast && <View style={styles.connector} />}

      {/* Node */}
      <View style={styles.node}>
        <View style={styles.iconContainer}>
          <Text style={styles.icon}>{STEP_ICONS[event.step] || '•'}</Text>
        </View>
        
        <View style={styles.content}>
          <View style={styles.titleRow}>
            <Text style={styles.title}>{event.title}</Text>
            <View style={styles.statusBadge}>
              <Text style={styles.statusText}>{STEP_EMOJI[event.status]}</Text>
            </View>
          </View>
          
          <Text style={styles.description}>{event.description}</Text>
          
          <View style={styles.metaRow}>
            <Text style={styles.timestamp}>{event.timestamp}</Text>
            {event.txHash && (
              <Text style={styles.txHash} numberOfLines={1} ellipsizeMode="middle">
                {event.txHash.slice(0, 8)}...{event.txHash.slice(-8)}
              </Text>
            )}
          </View>
        </View>
      </View>
    </View>
  );
}

function themedStyles({ color, tokens, stepColor, isLast, event }: any) {
  const isFailed = event.status === 'failed';
  
  return StyleSheet.create({
    container: {
      position: 'relative',
      paddingLeft: 20,
      paddingBottom: isLast ? 0 : 20,
    },
    connector: {
      position: 'absolute',
      left: 27,
      top: 40,
      width: 2,
      height: '100%',
      backgroundColor: isFailed 
        ? '#EF4444' 
        : event.status === 'completed' 
          ? '#10B981' 
          : color(tokens.border),
    },
    node: {
      flexDirection: 'row',
      alignItems: 'flex-start',
    },
    iconContainer: {
      width: 36,
      height: 36,
      borderRadius: 18,
      backgroundColor: stepColor.bg,
      alignItems: 'center',
      justifyContent: 'center',
      marginRight: 12,
      zIndex: 1,
    },
    icon: {
      fontSize: 16,
    },
    content: {
      flex: 1,
      paddingTop: 2,
    },
    titleRow: {
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'space-between',
      marginBottom: 4,
    },
    title: {
      fontSize: 15,
      fontWeight: event.status === 'current' ? '700' : '600',
      color: isFailed 
        ? '#EF4444' 
        : color(tokens.textPrimary),
    },
    statusBadge: {
      width: 22,
      height: 22,
      borderRadius: 11,
      backgroundColor: stepColor.bg,
      alignItems: 'center',
      justifyContent: 'center',
    },
    statusText: {
      fontSize: 12,
      fontWeight: '700',
      color: stepColor.text,
    },
    description: {
      fontSize: 13,
      color: color(tokens.textSecondary),
      lineHeight: 18,
      marginBottom: 6,
    },
    metaRow: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 12,
    },
    timestamp: {
      fontSize: 12,
      color: color(tokens.textMuted),
    },
    txHash: {
      fontSize: 11,
      color: color(tokens.textMuted),
      fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
      maxWidth: 120,
    },
  });
}