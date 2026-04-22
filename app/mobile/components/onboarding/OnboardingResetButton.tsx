import React from 'react';
import { Alert, TouchableOpacity, Text, StyleSheet } from 'react-native';
import { useOnboarding } from '../../hooks/useOnboarding';

interface OnboardingResetButtonProps {
  compact?: boolean;
}

export default function OnboardingResetButton({ compact = false }: OnboardingResetButtonProps) {
  const { resetOnboarding } = useOnboarding();

  const handleReset = () => {
    Alert.alert(
      'Reset Onboarding',
      'This will reset your onboarding progress and show you the welcome flow again. Are you sure?',
      [
        {
          text: 'Cancel',
          style: 'cancel',
        },
        {
          text: 'Reset',
          style: 'destructive',
          onPress: async () => {
            await resetOnboarding();
            Alert.alert('Onboarding Reset', 'Onboarding has been reset. The app will now show the welcome flow.');
          },
        },
      ]
    );
  };

  if (compact) {
    return (
      <TouchableOpacity style={styles.compactButton} onPress={handleReset}>
        <Text style={styles.compactButtonText}>Reset Onboarding</Text>
      </TouchableOpacity>
    );
  }

  return (
    <TouchableOpacity style={styles.button} onPress={handleReset}>
      <Text style={styles.buttonText}>Reset Onboarding</Text>
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  button: {
    backgroundColor: '#FEE2E2',
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#FCA5A5',
    alignItems: 'center',
    marginVertical: 8,
  },
  compactButton: {
    paddingVertical: 8,
    paddingHorizontal: 12,
    borderRadius: 4,
    borderWidth: 1,
    borderColor: '#FCA5A5',
    alignItems: 'center',
  },
  buttonText: {
    color: '#DC2626',
    fontSize: 16,
    fontWeight: '600',
  },
  compactButtonText: {
    color: '#DC2626',
    fontSize: 14,
    fontWeight: '600',
  },
});
