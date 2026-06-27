import React from "react";
import { StyleSheet, TouchableOpacity, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { ThemedText } from "../themed-text";
import { ThemedView } from "../themed-view";
import { useTheme } from "../../src/theme/ThemeContext";
import { mapContractError } from "../../utils/contract-error-mapper";

interface ContractErrorStateProps {
  error: any;
  onRetry?: () => void;
  onAction?: (actionType: string) => void;
  onDismiss?: () => void;
}

/**
 * ContractErrorState parses any smart contract / backend error and renders a
 * detailed, actionable recovery view for mobile users.
 */
export function ContractErrorState({
  error,
  onRetry,
  onAction,
  onDismiss,
}: ContractErrorStateProps) {
  const { theme } = useTheme();
  const mapped = mapContractError(error);

  // Map action type to appropriate Ionicons
  const getIconName = (): keyof typeof Ionicons.glyphMap => {
    switch (mapped.actionType) {
      case "contact_support":
        return "help-circle-outline";
      case "check_network":
        return "wifi-outline";
      case "refresh_balance":
        return "refresh-outline";
      case "go_back":
        return "arrow-back-outline";
      case "retry":
        return "repeat-outline";
      default:
        return "alert-circle-outline";
    }
  };

  const handlePrimaryPress = () => {
    if (mapped.actionType === "retry" && onRetry) {
      onRetry();
    } else if (onAction) {
      onAction(mapped.actionType);
    } else if (mapped.actionType === "go_back" && onDismiss) {
      onDismiss();
    }
  };

  const showSecondary = mapped.actionType !== "dismiss" && onDismiss;

  return (
    <ThemedView style={styles.container}>
      {/* Visual Indicator */}
      <View style={[styles.iconContainer, { backgroundColor: theme.status.errorBg || "#FEE2E2" }]}>
        <Ionicons name={getIconName()} size={48} color={theme.status.error || "#DC2626"} />
      </View>

      {/* Error Info */}
      <ThemedText type="subtitle" style={[styles.title, { color: theme.textPrimary }]}>
        {mapped.title}
      </ThemedText>
      
      <ThemedText style={[styles.message, { color: theme.textSecondary }]}>
        {mapped.message}
      </ThemedText>

      {/* Actionable Recovery Guidance Box */}
      <View
        style={[
          styles.guidanceBox,
          {
            backgroundColor: theme.status.warningBg || "#FEF3C7",
            borderColor: theme.status.warning || "#F59E0B",
          },
        ]}
      >
        <View style={styles.guidanceHeader}>
          <Ionicons name="bulb-outline" size={18} color={theme.status.warning || "#F59E0B"} style={styles.guidanceIcon} />
          <ThemedText style={[styles.guidanceTitle, { color: theme.textPrimary }]}>
            How to resolve this:
          </ThemedText>
        </View>
        <ThemedText style={[styles.guidanceText, { color: theme.textSecondary }]}>
          {mapped.recoveryGuidance}
        </ThemedText>
      </View>

      {/* Error Metadata / Code Badge */}
      <View style={[styles.badge, { backgroundColor: theme.divider || "#E5E7EB" }]}>
        <ThemedText style={[styles.badgeText, { color: theme.textMuted }]}>
          {`Code: ${mapped.code}`}
        </ThemedText>
      </View>

      {/* Actions Section */}
      <View style={styles.buttonContainer}>
        <TouchableOpacity
          testID="error-primary-button"
          style={[styles.primaryButton, { backgroundColor: theme.tint || theme.buttonPrimaryBg }]}
          onPress={handlePrimaryPress}
          activeOpacity={0.8}
        >
          <ThemedText style={[styles.primaryButtonText, { color: theme.buttonPrimaryText }]}>
            {mapped.actionLabel || "Resolve Issue"}
          </ThemedText>
        </TouchableOpacity>

        {showSecondary && (
          <TouchableOpacity
            testID="error-secondary-button"
            style={[styles.secondaryButton, { borderColor: theme.divider || "#E5E7EB" }]}
            onPress={onDismiss}
            activeOpacity={0.8}
          >
            <ThemedText style={[styles.secondaryButtonText, { color: theme.textSecondary }]}>
              Dismiss
            </ThemedText>
          </TouchableOpacity>
        )}
      </View>
    </ThemedView>
  );
}

const styles = StyleSheet.create({
  container: {
    alignItems: "center",
    justifyContent: "center",
    padding: 24,
    borderRadius: 20,
    width: "100%",
  },
  iconContainer: {
    width: 80,
    height: 80,
    borderRadius: 40,
    alignItems: "center",
    justifyContent: "center",
    marginBottom: 20,
  },
  title: {
    textAlign: "center",
    fontWeight: "700",
    fontSize: 20,
    marginBottom: 10,
  },
  message: {
    textAlign: "center",
    fontSize: 15,
    lineHeight: 22,
    marginBottom: 24,
    paddingHorizontal: 8,
  },
  guidanceBox: {
    borderWidth: 1,
    borderRadius: 14,
    padding: 16,
    width: "100%",
    marginBottom: 20,
  },
  guidanceHeader: {
    flexDirection: "row",
    alignItems: "center",
    marginBottom: 6,
  },
  guidanceIcon: {
    marginRight: 6,
  },
  guidanceTitle: {
    fontWeight: "700",
    fontSize: 14,
  },
  guidanceText: {
    fontSize: 13,
    lineHeight: 18,
  },
  badge: {
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 8,
    marginBottom: 24,
  },
  badgeText: {
    fontSize: 11,
    fontWeight: "600",
  },
  buttonContainer: {
    width: "100%",
    gap: 12,
  },
  primaryButton: {
    paddingVertical: 14,
    borderRadius: 12,
    width: "100%",
    alignItems: "center",
    justifyContent: "center",
    elevation: 2,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
  },
  primaryButtonText: {
    fontWeight: "700",
    fontSize: 16,
  },
  secondaryButton: {
    paddingVertical: 14,
    borderRadius: 12,
    borderWidth: 1,
    width: "100%",
    alignItems: "center",
    justifyContent: "center",
  },
  secondaryButtonText: {
    fontWeight: "600",
    fontSize: 15,
  },
});
