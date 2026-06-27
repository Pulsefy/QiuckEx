import { Ionicons } from "@expo/vector-icons";
import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { useWalletContext } from "../../hooks/useWalletContext";
import { useTheme } from "../../src/theme/ThemeContext";
import type { WalletErrorCode } from "../../types/wallet";

const BANNER_CONFIG: Record<
  string,
  {
    icon: keyof typeof Ionicons.glyphMap;
    title: string;
    instructions: string[];
  }
> = {
  session_expired: {
    icon: "time-outline",
    title: "Session Expired",
    instructions: [
      "Your previous session has expired (sessions are valid for 7 days).",
      "Connect your wallet again to continue.",
    ],
  },
  session_environment_mismatch: {
    icon: "git-branch-outline",
    title: "Environment Changed",
    instructions: [
      "The app environment or branch has changed since your last session.",
      "Reconnect your wallet to continue in this environment.",
    ],
  },
  session_corrupted: {
    icon: "warning-outline",
    title: "Session Data Corrupted",
    instructions: [
      "Your saved session data could not be read.",
      "Connect your wallet again to create a fresh session.",
    ],
  },
};

const DEFAULT_CONFIG = {
  icon: "alert-circle-outline" as keyof typeof Ionicons.glyphMap,
  title: "Session Issue",
  instructions: ["There was an issue with your saved session. Please reconnect your wallet."],
};

export const StaleSessionBanner: React.FC<{
  onReconnect?: () => void;
  onDismiss?: () => void;
}> = ({ onReconnect, onDismiss }) => {
  const { wallet, clearError } = useWalletContext();
  const { theme } = useTheme();

  if (!wallet.error) return null;

  const config = BANNER_CONFIG[wallet.error.code as WalletErrorCode] ?? DEFAULT_CONFIG;

  return (
    <View
      style={[
        styles.container,
        { backgroundColor: theme.status.warningBg, borderColor: theme.status.warning },
      ]}
    >
      <View style={styles.header}>
        <Ionicons name={config.icon} size={22} color={theme.status.warning} />
        <Text style={[styles.title, { color: theme.textPrimary }]}>{config.title}</Text>
        {onDismiss ? (
          <Pressable onPress={onDismiss} style={styles.dismissHitbox}>
            <Ionicons name="close-outline" size={20} color={theme.textMuted} />
          </Pressable>
        ) : null}
      </View>

      {config.instructions.map((line, i) => (
        <Text key={i} style={[styles.instruction, { color: theme.textSecondary }]}>
          {line}
        </Text>
      ))}

      {onReconnect ? (
        <Pressable
          style={[styles.reconnectBtn, { backgroundColor: theme.buttonPrimaryBg }]}
          onPress={() => {
            clearError();
            onReconnect();
          }}
        >
          <Ionicons name="refresh-outline" size={16} color={theme.buttonPrimaryText} />
          <Text style={[styles.reconnectText, { color: theme.buttonPrimaryText }]}>
            Reconnect Wallet
          </Text>
        </Pressable>
      ) : null}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    borderWidth: 1,
    borderRadius: 14,
    padding: 16,
    marginBottom: 18,
  },
  header: {
    flexDirection: "row",
    alignItems: "center",
    marginBottom: 10,
  },
  title: {
    fontSize: 16,
    fontWeight: "700",
    marginLeft: 8,
    flex: 1,
  },
  dismissHitbox: {
    padding: 4,
  },
  instruction: {
    fontSize: 14,
    lineHeight: 20,
    marginBottom: 4,
  },
  reconnectBtn: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    paddingVertical: 12,
    borderRadius: 10,
    marginTop: 12,
    gap: 6,
  },
  reconnectText: {
    fontSize: 14,
    fontWeight: "700",
  },
});
