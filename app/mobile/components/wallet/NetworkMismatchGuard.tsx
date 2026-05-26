import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity, ViewStyle } from 'react-native';
import { useNetworkGuardContext } from '../../contexts/NetworkGuardContext';

interface GuardProps {
  children: React.ReactNode;
  onBlocked?: () => void;
  style?: ViewStyle;
  overlayStyle?: ViewStyle;
  disabled?: boolean;
}

/**
 * Wrapper component that blocks interaction with its children if a network mismatch is detected.
 */
export const NetworkMismatchGuard: React.FC<GuardProps> = ({
  children,
  onBlocked,
  style,
  overlayStyle,
  disabled = false,
}) => {
  const { guard } = useNetworkGuardContext();
  const isBlocked = !disabled && guard.isMismatched;

  if (!isBlocked) return <View style={style}>{children}</View>;

  return (
    <View style={[styles.container, style]}>
      <View style={styles.content}>{children}</View>
      <TouchableOpacity
        activeOpacity={1}
        onPress={onBlocked}
        style={[styles.overlay, overlayStyle]}
      >
        <View style={styles.badge}>
          <Text style={styles.lockIcon}>🔒</Text>
          <Text style={styles.blockedText}>Action Blocked</Text>
          <Text style={styles.hintText}>Tap for help</Text>
        </View>
      </TouchableOpacity>
    </View>
  );
};

/**
 * Specialized button variant that automatically handles blocked state UI.
 */
export const NetworkMismatchGuardButton: React.FC<{
  children: string;
  onPress?: () => void;
  onBlocked?: () => void;
  style?: ViewStyle;
  disabled?: boolean;
}> = ({ children, onPress, onBlocked, style, disabled }) => {
  const { guard } = useNetworkGuardContext();
  const isBlocked = !disabled && guard.isMismatched;

  return (
    <TouchableOpacity
      onPress={isBlocked ? onBlocked : onPress}
      disabled={disabled && !isBlocked}
      style={[styles.button, isBlocked && styles.buttonDisabled, style]}
    >
      <Text style={[styles.buttonText, isBlocked && styles.buttonTextDisabled]}>
        {isBlocked ? `🔒 Action Blocked` : children}
      </Text>
    </TouchableOpacity>
  );
};

const styles = StyleSheet.create({
  container: { position: 'relative' },
  content: { opacity: 0.4 },
  overlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(255, 255, 255, 0.6)',
    justifyContent: 'center',
    alignItems: 'center',
    borderRadius: 12,
  },
  badge: {
    backgroundColor: '#1f2937',
    paddingVertical: 8,
    paddingHorizontal: 16,
    borderRadius: 20,
    alignItems: 'center',
    elevation: 4,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 3.84,
  },
  lockIcon: { fontSize: 18, marginBottom: 2 },
  blockedText: { fontSize: 12, fontWeight: 'bold', color: 'white' },
  hintText: { fontSize: 10, color: '#9ca3af' },
  button: {
    backgroundColor: '#3b82f6',
    padding: 16,
    borderRadius: 12,
    alignItems: 'center',
  },
  buttonDisabled: { backgroundColor: '#d1d5db' },
  buttonText: { color: 'white', fontWeight: 'bold' },
  buttonTextDisabled: { color: '#6b7280' },
});