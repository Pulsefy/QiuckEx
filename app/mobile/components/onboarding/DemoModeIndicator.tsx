import { Ionicons } from "@expo/vector-icons";
import React from "react";
import { StyleSheet, Text, View } from "react-native";
import { useTheme } from "../../src/theme/ThemeContext";

interface DemoModeIndicatorProps {
  visible: boolean;
  compact?: boolean;
}

export default function DemoModeIndicator({
  visible,
  compact = false,
}: DemoModeIndicatorProps) {
  const { theme } = useTheme();

  if (!visible) return null;

  if (compact) {
    return (
      <View
        style={[
          styles.compactContainer,
          {
            backgroundColor: theme.status.infoBg,
            borderColor: theme.status.info,
          },
        ]}
      >
        <Ionicons name="school-outline" size={16} color={theme.status.info} />
        <Text style={[styles.compactText, { color: theme.status.info }]}>
          DEMO
        </Text>
      </View>
    );
  }

  return (
    <View
      style={[
        styles.container,
        {
          backgroundColor: theme.status.infoBg,
          borderColor: theme.status.info,
        },
      ]}
    >
      <Ionicons name="school-outline" size={20} color={theme.status.info} />
      <Text style={[styles.text, { color: theme.status.info }]}>
        Demo Mode - Practice with testnet funds
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 8,
    borderWidth: 1,
    marginVertical: 8,
  },
  compactContainer: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 4,
    paddingHorizontal: 8,
    borderRadius: 4,
    borderWidth: 1,
  },
  text: {
    fontSize: 14,
    fontWeight: "600",
    marginLeft: 8,
    flex: 1,
  },
  compactText: {
    fontSize: 12,
    fontWeight: "700",
    marginLeft: 4,
  },
});
