import React from "react";
import { Alert, StyleSheet, Text, TouchableOpacity } from "react-native";
import { useOnboarding } from "../../hooks/useOnboarding";
import { useTheme } from "../../src/theme/ThemeContext";

interface OnboardingResetButtonProps {
  compact?: boolean;
}

export default function OnboardingResetButton({
  compact = false,
}: OnboardingResetButtonProps) {
  const { resetOnboarding } = useOnboarding();
  const { theme } = useTheme();

  const handleReset = () => {
    Alert.alert(
      "Reset Onboarding",
      "This will reset your onboarding progress and show you the welcome flow again. Are you sure?",
      [
        {
          text: "Cancel",
          style: "cancel",
        },
        {
          text: "Reset",
          style: "destructive",
          onPress: async () => {
            await resetOnboarding();
            Alert.alert(
              "Onboarding Reset",
              "Onboarding has been reset. The app will now show the welcome flow.",
            );
          },
        },
      ],
    );
  };

  if (compact) {
    return (
      <TouchableOpacity
        style={[styles.compactButton, { borderColor: theme.status.error }]}
        onPress={handleReset}
      >
        <Text style={[styles.compactButtonText, { color: theme.status.error }]}>
          Reset Onboarding
        </Text>
      </TouchableOpacity>
    );
  }

  return (
    <TouchableOpacity
      style={[
        styles.button,
        {
          backgroundColor: theme.status.errorBg,
          borderColor: theme.status.error,
        },
      ]}
      onPress={handleReset}
    >
      <Text style={[styles.buttonText, { color: theme.status.error }]}>
        Reset Onboarding
      </Text>
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  button: {
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 8,
    borderWidth: 1,
    alignItems: "center",
    marginVertical: 8,
  },
  compactButton: {
    paddingVertical: 8,
    paddingHorizontal: 12,
    borderRadius: 4,
    borderWidth: 1,
    alignItems: "center",
  },
  buttonText: {
    fontSize: 16,
    fontWeight: "600",
  },
  compactButtonText: {
    fontSize: 14,
    fontWeight: "600",
  },
});
