import React from "react";
import { StyleSheet, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { Ionicons } from "@expo/vector-icons";
import { ThemedText } from "../themed-text";
import { useNetworkStatus } from "../../hooks/use-network-status";
import { useTheme } from "../../src/theme/ThemeContext";

/**
 * A banner that appears at the top of the screen when the device is offline.
 */
export function OfflineBanner() {
  const { isConnected } = useNetworkStatus();
  const insets = useSafeAreaInsets();
  const { theme } = useTheme();

  // Offline banner uses warning colours from the theme
  const backgroundColor = theme.status.warning;
  const textColor = theme.buttonPrimaryText;

  if (isConnected !== false) {
    return null;
  }

  return (
    <View
      style={[styles.container, { paddingTop: insets.top, backgroundColor }]}
    >
      <View style={styles.content}>
        <Ionicons name="cloud-offline" size={20} color={textColor} />
        <ThemedText style={[styles.text, { color: textColor }]}>
          You are currently offline. Some features may be unavailable.
        </ThemedText>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    width: "100%",
    zIndex: 1000,
    elevation: 10,
  },
  content: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    paddingVertical: 8,
    paddingHorizontal: 16,
    gap: 8,
  },
  text: {
    fontSize: 14,
    fontWeight: "600",
  },
});
