import React, { useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import {
  APP_ENVIRONMENT,
  APP_VERSION,
  BUILD_METADATA,
  STELLAR_NETWORK,
} from "../src/config/build";
import { useTheme } from "../src/theme/ThemeContext";

interface ChecklistItem {
  key: string;
  label: string;
  description: string;
}

const CHECKLIST: ChecklistItem[] = [
  {
    key: "deep-links",
    label: "Deep Links",
    description: "Verify quickex:// and https://quickex.to links open the app and route to the correct screen.",
  },
  {
    key: "wallet-connect",
    label: "Wallet Connect",
    description: "Connect a Stellar wallet (Freighter, Lobstr, etc.) and verify the connection persists across app restarts.",
  },
  {
    key: "pay-flow",
    label: "Payment Flow",
    description: "Send a test payment via QR scan, payment link, and wallet-to-wallet transfer. Verify transaction history updates.",
  },
  {
    key: "push-notifications",
    label: "Push Notifications",
    description: "Receive and tap a push notification. Verify it routes to the correct transaction/escrow/listing detail screen.",
  },
  {
    key: "network-guard",
    label: "Network Guard",
    description: "Switch wallet to mainnet and verify the network mismatch warning appears. Switch back to testnet and confirm the warning clears.",
  },
  {
    key: "offline-mode",
    label: "Offline Resilience",
    description: "Enable airplane mode. Verify offline banner displays and the app does not crash. Reconnect and verify normal operation resumes.",
  },
  {
    key: "biometric-lock",
    label: "Biometric Lock",
    description: "Enable biometric lock in settings. Lock the app and verify it re-prompts for authentication on resume.",
  },
  {
    key: "contacts-sync",
    label: "Contacts Sync",
    description: "Add, edit, and delete a contact. Verify changes are reflected immediately and persist after app restart.",
  },
  {
    key: "payment-link-gen",
    label: "Payment Link Generation",
    description: "Generate a payment link with various amounts and assets. Verify the link opens the payment confirmation screen.",
  },
  {
    key: "escrow-flow",
    label: "Escrow Flow",
    description: "Create an escrow transaction, verify funding, and complete the release flow on testnet.",
  },
];

export default function QaSmokeChecklistScreen() {
  const { theme } = useTheme();
  const [checked, setChecked] = useState<Set<string>>(new Set());

  function toggleItem(key: string) {
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  }

  const isStaging = APP_ENVIRONMENT === "staging";

  return (
    <SafeAreaView
      style={[styles.container, { backgroundColor: theme.background }]}
      edges={["top", "bottom"]}
    >
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <View style={styles.header}>
          <Text style={[styles.title, { color: theme.textPrimary }]}>
            QA Smoke Checklist
          </Text>
          <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
            {isStaging
              ? "Staging Build Validation — run through each item before shipping."
              : "Reference checklist (this screen is primarily for staging builds)."}
          </Text>
        </View>

        <View style={[styles.buildInfo, { backgroundColor: theme.surface, borderColor: theme.border }]}>
          <BuildInfoRow label="Environment" value={APP_ENVIRONMENT} theme={theme} />
          <BuildInfoRow label="Network" value={STELLAR_NETWORK} theme={theme} />
          <BuildInfoRow label="Version" value={APP_VERSION} theme={theme} />
          <BuildInfoRow label="Build" value={BUILD_METADATA} theme={theme} />
        </View>

        {CHECKLIST.map((item) => {
          const isChecked = checked.has(item.key);
          return (
            <Pressable
              key={item.key}
              style={[
                styles.checkItem,
                {
                  backgroundColor: isChecked ? theme.status.success + "15" : theme.surface,
                  borderColor: isChecked ? theme.status.success : theme.border,
                },
              ]}
              onPress={() => toggleItem(item.key)}
            >
              <View style={styles.checkbox}>
                <Text style={{ fontSize: 18 }}>
                  {isChecked ? "✅" : "⬜"}
                </Text>
              </View>
              <View style={styles.checkContent}>
                <Text
                  style={[
                    styles.checkLabel,
                    {
                      color: theme.textPrimary,
                      textDecorationLine: isChecked ? "line-through" : "none",
                    },
                  ]}
                >
                  {item.label}
                </Text>
                <Text
                  style={[
                    styles.checkDescription,
                    { color: theme.textSecondary },
                  ]}
                >
                  {item.description}
                </Text>
              </View>
            </Pressable>
          );
        })}

        {checked.size > 0 && (
          <Pressable
            style={[styles.resetButton, { backgroundColor: theme.status.error }]}
            onPress={() => setChecked(new Set())}
          >
            <Text style={styles.resetButtonText}>Reset All</Text>
          </Pressable>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

function BuildInfoRow({
  label,
  value,
  theme,
}: {
  label: string;
  value: string;
  theme: any;
}) {
  return (
    <View style={styles.buildRow}>
      <Text style={[styles.buildLabel, { color: theme.textSecondary }]}>
        {label}
      </Text>
      <Text style={[styles.buildValue, { color: theme.textPrimary }]}>
        {value}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  scrollContent: {
    padding: 16,
    paddingBottom: 40,
    gap: 12,
  },
  header: {
    marginBottom: 4,
  },
  title: {
    fontSize: 24,
    fontWeight: "700",
    marginBottom: 4,
  },
  subtitle: {
    fontSize: 14,
    lineHeight: 20,
  },
  buildInfo: {
    borderRadius: 12,
    borderWidth: 1,
    padding: 12,
    gap: 6,
  },
  buildRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  buildLabel: {
    fontSize: 13,
    fontWeight: "500",
  },
  buildValue: {
    fontSize: 13,
    fontWeight: "700",
    fontFamily: "monospace",
  },
  checkItem: {
    flexDirection: "row",
    alignItems: "flex-start",
    borderRadius: 12,
    borderWidth: 1,
    padding: 14,
    gap: 12,
  },
  checkbox: {
    paddingTop: 1,
  },
  checkContent: {
    flex: 1,
    gap: 4,
  },
  checkLabel: {
    fontSize: 15,
    fontWeight: "700",
  },
  checkDescription: {
    fontSize: 12,
    lineHeight: 17,
  },
  resetButton: {
    borderRadius: 12,
    paddingVertical: 14,
    paddingHorizontal: 16,
    alignItems: "center",
    marginTop: 8,
  },
  resetButtonText: {
    color: "#FFFFFF",
    fontSize: 15,
    fontWeight: "700",
  },
});
