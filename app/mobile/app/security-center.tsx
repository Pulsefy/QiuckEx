import { Link } from "expo-router";
import React, { useEffect, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import { useSecurity } from "@/hooks/use-security";
import {
  getWalletSession,
  isSessionRestorable,
} from "@/services/wallet-session";
import { useTheme } from "../src/theme/ThemeContext";

interface SecurityCheckItem {
  id: string;
  title: string;
  description: string;
  status: "pass" | "warning" | "error";
  actionText?: string;
  actionLink?: string;
}

export default function SecurityCenterScreen() {
  const { theme } = useTheme();
  const { isBiometricAvailable, hasPinConfigured, settings } = useSecurity();

  const [securityItems, setSecurityItems] = useState<SecurityCheckItem[]>([]);

  useEffect(() => {
    const loadSecurityChecks = async () => {
      const items: SecurityCheckItem[] = [];

      // Check biometrics
      if (isBiometricAvailable) {
        if (settings.biometricLockEnabled) {
          items.push({
            id: "biometrics",
            title: "Biometric Lock Enabled",
            description:
              "Your device biometrics are protecting sensitive actions.",
            status: "pass",
          });
        } else {
          items.push({
            id: "biometrics",
            title: "Enable Biometric Lock",
            description:
              "Add an extra layer of security with biometric authentication.",
            status: "warning",
            actionText: "Enable",
            actionLink: "/security",
          });
        }
      } else {
        items.push({
          id: "biometrics",
          title: "Biometrics Unavailable",
          description: "Biometric hardware is not available on this device.",
          status: "warning",
        });
      }

      // Check PIN
      if (hasPinConfigured) {
        items.push({
          id: "pin",
          title: "Fallback PIN Configured",
          description:
            "You have a secure PIN as a backup authentication method.",
          status: "pass",
        });
      } else {
        items.push({
          id: "pin",
          title: "Set Fallback PIN",
          description:
            "Configure a PIN for when biometrics fail or are unavailable.",
          status: "error",
          actionText: "Set PIN",
          actionLink: "/security",
        });
      }

      // Check wallet session
      const session = await getWalletSession();
      if (session) {
        const isRestorable = isSessionRestorable(session);
        if (isRestorable) {
          items.push({
            id: "session",
            title: "Active Wallet Session",
            description: "Your wallet session is active and secure.",
            status: "pass",
          });
        } else {
          items.push({
            id: "session",
            title: "Session Expired",
            description:
              "Your wallet session has expired. Reconnect your wallet.",
            status: "warning",
            actionText: "Reconnect",
            actionLink: "/",
          });
        }
      } else {
        items.push({
          id: "session",
          title: "No Wallet Connected",
          description: "Connect a wallet to start using the app securely.",
          status: "warning",
          actionText: "Connect Wallet",
          actionLink: "/",
        });
      }

      setSecurityItems(items);
    };

    loadSecurityChecks();
  }, [isBiometricAvailable, hasPinConfigured, settings]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case "pass":
        return "#10B981";
      case "warning":
        return "#F59E0B";
      case "error":
        return "#EF4444";
      default:
        return theme.textSecondary;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "pass":
        return "✓";
      case "warning":
        return "⚠";
      case "error":
        return "!";
      default:
        return "";
    }
  };

  const overallScore = securityItems.filter(
    (item) => item.status === "pass",
  ).length;
  const totalItems = securityItems.length;
  const securityLevel =
    overallScore === totalItems
      ? "Strong"
      : overallScore >= totalItems / 2
        ? "Moderate"
        : "Needs Attention";

  return (
    <SafeAreaView
      style={[styles.container, { backgroundColor: theme.background }]}
    >
      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.content}
        showsVerticalScrollIndicator={false}
      >
        <Text style={[styles.title, { color: theme.textPrimary }]}>
          Security Center
        </Text>
        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
          Review your security posture and take recommended actions.
        </Text>

        {/* Overall Security Score */}
        <View
          style={[
            styles.scoreCard,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <Text style={[styles.scoreLabel, { color: theme.textSecondary }]}>
            Security Level
          </Text>
          <Text
            style={[
              styles.scoreValue,
              {
                color:
                  securityLevel === "Strong"
                    ? "#10B981"
                    : securityLevel === "Moderate"
                      ? "#F59E0B"
                      : "#EF4444",
              },
            ]}
          >
            {securityLevel}
          </Text>
          <Text style={[styles.scoreDetail, { color: theme.textSecondary }]}>
            {overallScore} of {totalItems} checks passed
          </Text>
        </View>

        {/* Security Checklist */}
        <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
          Security Checklist
        </Text>

        {securityItems.map((item) => (
          <View
            key={item.id}
            style={[
              styles.checkItem,
              {
                backgroundColor: theme.surface,
                borderColor: theme.border,
                borderLeftColor: getStatusColor(item.status),
              },
            ]}
          >
            <View style={styles.checkHeader}>
              <View
                style={[
                  styles.statusIcon,
                  { backgroundColor: getStatusColor(item.status) },
                ]}
              >
                <Text style={styles.statusIconText}>
                  {getStatusIcon(item.status)}
                </Text>
              </View>
              <View style={styles.checkContent}>
                <Text style={[styles.checkTitle, { color: theme.textPrimary }]}>
                  {item.title}
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
            </View>
            {item.actionText && item.actionLink && (
              <Link href={item.actionLink} asChild>
                <Pressable
                  style={[
                    styles.actionButton,
                    { backgroundColor: theme.buttonPrimaryBg },
                  ]}
                >
                  <Text
                    style={[
                      styles.actionButtonText,
                      { color: theme.buttonPrimaryText },
                    ]}
                  >
                    {item.actionText}
                  </Text>
                </Pressable>
              </Link>
            )}
          </View>
        ))}

        {/* Quick Links */}
        <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
          Quick Settings
        </Text>

        <View
          style={[
            styles.card,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <Link href="/security" asChild>
            <Pressable style={styles.quickLink}>
              <Text
                style={[styles.quickLinkText, { color: theme.textPrimary }]}
              >
                Security Settings
              </Text>
              <Text
                style={[styles.quickLinkArrow, { color: theme.textSecondary }]}
              >
                →
              </Text>
            </Pressable>
          </Link>

          <View style={[styles.divider, { backgroundColor: theme.border }]} />

          <Link href="/settings" asChild>
            <Pressable style={styles.quickLink}>
              <Text
                style={[styles.quickLinkText, { color: theme.textPrimary }]}
              >
                Notification Settings
              </Text>
              <Text
                style={[styles.quickLinkArrow, { color: theme.textSecondary }]}
              >
                →
              </Text>
            </Pressable>
          </Link>

          <View style={[styles.divider, { backgroundColor: theme.border }]} />

          <Link href="/" asChild>
            <Pressable style={styles.quickLink}>
              <Text
                style={[styles.quickLinkText, { color: theme.textPrimary }]}
              >
                Wallet Connection
              </Text>
              <Text
                style={[styles.quickLinkArrow, { color: theme.textSecondary }]}
              >
                →
              </Text>
            </Pressable>
          </Link>
        </View>

        {/* Security Note */}
        <View
          style={[
            styles.noteCard,
            {
              backgroundColor: theme.surfaceElevated,
              borderColor: theme.borderLight,
            },
          ]}
        >
          <Text style={[styles.noteTitle, { color: theme.textPrimary }]}>
            🔒 Security Note
          </Text>
          <Text style={[styles.noteText, { color: theme.textSecondary }]}>
            No private keys or sensitive data are displayed in this screen. All
            security checks are performed locally on your device.
          </Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  scrollView: {
    flex: 1,
  },
  content: {
    padding: 24,
    gap: 20,
  },
  title: {
    fontSize: 34,
    fontWeight: "800",
  },
  subtitle: {
    fontSize: 16,
    lineHeight: 22,
  },
  scoreCard: {
    borderRadius: 16,
    padding: 20,
    borderWidth: 1,
    alignItems: "center",
  },
  scoreLabel: {
    fontSize: 14,
    fontWeight: "600",
    textTransform: "uppercase",
  },
  scoreValue: {
    fontSize: 32,
    fontWeight: "800",
    marginTop: 8,
  },
  scoreDetail: {
    fontSize: 14,
    marginTop: 4,
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: "700",
  },
  checkItem: {
    borderRadius: 12,
    padding: 16,
    borderWidth: 1,
    borderLeftWidth: 4,
    gap: 12,
  },
  checkHeader: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 12,
  },
  statusIcon: {
    width: 28,
    height: 28,
    borderRadius: 14,
    alignItems: "center",
    justifyContent: "center",
  },
  statusIconText: {
    color: "white",
    fontSize: 16,
    fontWeight: "700",
  },
  checkContent: {
    flex: 1,
  },
  checkTitle: {
    fontSize: 16,
    fontWeight: "700",
    marginBottom: 4,
  },
  checkDescription: {
    fontSize: 14,
    lineHeight: 20,
  },
  actionButton: {
    borderRadius: 8,
    paddingVertical: 10,
    paddingHorizontal: 16,
    alignSelf: "flex-start",
  },
  actionButtonText: {
    fontSize: 14,
    fontWeight: "700",
  },
  card: {
    borderRadius: 16,
    padding: 16,
    borderWidth: 1,
  },
  quickLink: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 12,
  },
  quickLinkText: {
    fontSize: 16,
    fontWeight: "600",
  },
  quickLinkArrow: {
    fontSize: 20,
  },
  divider: {
    height: 1,
  },
  noteCard: {
    borderRadius: 12,
    padding: 16,
    borderWidth: 1,
  },
  noteTitle: {
    fontSize: 16,
    fontWeight: "700",
    marginBottom: 8,
  },
  noteText: {
    fontSize: 14,
    lineHeight: 20,
  },
});
