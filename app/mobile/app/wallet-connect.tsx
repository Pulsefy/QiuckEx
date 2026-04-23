import { Ionicons } from "@expo/vector-icons";
import { useLocalSearchParams, useRouter } from "expo-router";
import React, { useEffect, useState } from "react";
import { Alert, Pressable, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import { useNotifications } from "../components/notifications/NotificationContext";
import { useNetworkStatus } from "../hooks/use-network-status";
import { useOnboarding } from "../hooks/useOnboarding";
import { useSecurity } from "../hooks/use-security";
import {
  clearWalletSession,
  saveWalletSession,
  type WalletNetwork,
} from "../services/wallet-session";
import { useTheme } from "../src/theme/ThemeContext";

function generateMockSessionToken() {
  return `qex_session_${Math.random().toString(36).slice(2, 14)}`;
}

const DEMO_PUBLIC_KEY =
  "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP";
const MOCK_PUBLIC_KEY = DEMO_PUBLIC_KEY;

export default function WalletConnectScreen() {
  const router = useRouter();
  const params = useLocalSearchParams<{ demo?: string }>();
  const { theme } = useTheme();
  const { isConnected } = useNetworkStatus();
  const { trackOnboardingEvent } = useOnboarding();
  const { syncNow } = useNotifications();
  const {
    authenticateForSensitiveAction,
    clearSensitiveSessionToken,
    getSensitiveSessionToken,
    saveSensitiveSessionToken,
  } = useSecurity();

  const [connected, setConnected] = useState(false);
  const [network, setNetwork] = useState<WalletNetwork>("testnet");
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [sessionTokenPreview, setSessionTokenPreview] = useState<string | null>(
    null,
  );
  const [isDemoMode, setIsDemoMode] = useState(false);

  useEffect(() => {
    const nextDemoMode = params.demo === "true";
    setIsDemoMode(nextDemoMode);
    if (nextDemoMode) {
      setNetwork("testnet");
    }
  }, [params.demo]);

  const toggleNetwork = () => {
    setNetwork((current) => (current === "mainnet" ? "testnet" : "mainnet"));
  };

  const handleConnect = async () => {
    const nextPublicKey = isDemoMode ? DEMO_PUBLIC_KEY : MOCK_PUBLIC_KEY;

    setConnected(true);
    setPublicKey(nextPublicKey);
    await saveSensitiveSessionToken(generateMockSessionToken());
    await saveWalletSession({
      publicKey: nextPublicKey,
      network,
      connectedAt: Date.now(),
    });

    await trackOnboardingEvent("wallet_connected", {
      demo_mode: isDemoMode,
      network,
      timestamp: Date.now(),
    });

    await syncNow();
  };

  const handleDisconnect = async () => {
    setConnected(false);
    setPublicKey(null);
    setSessionTokenPreview(null);
    await clearSensitiveSessionToken();
    await clearWalletSession();
    await syncNow();
  };

  const revealSessionToken = async () => {
    const authorized = await authenticateForSensitiveAction(
      "sensitive_data_access",
    );

    if (!authorized) {
      Alert.alert(
        "Authentication Required",
        "Use biometrics or fallback PIN to reveal secure session data.",
      );
      return;
    }

    const token = await getSensitiveSessionToken();
    if (!token) {
      Alert.alert("No token found", "No secure session token is currently stored.");
      return;
    }

    setSessionTokenPreview(`${token.slice(0, 8)}...${token.slice(-4)}`);
  };

  return (
    <SafeAreaView
      style={[styles.container, { backgroundColor: theme.background }]}
    >
      <View style={styles.content}>
        <Text style={[styles.title, { color: theme.textPrimary }]}>
          Wallet Connection
        </Text>
        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
          Connect a wallet once and QuickEx will use that account for recent
          activity sync, notification badges, and transaction history.
        </Text>

        {isDemoMode ? (
          <View
            style={[
              styles.demoBanner,
              {
                backgroundColor: theme.status.infoBg,
                borderColor: theme.status.info,
              },
            ]}
          >
            <Ionicons
              name="school-outline"
              size={20}
              color={theme.status.info}
            />
            <Text style={[styles.demoBannerText, { color: theme.status.info }]}>
              Demo mode uses a testnet account so background sync is easy to
              verify in recordings.
            </Text>
          </View>
        ) : null}

        <View
          style={[
            styles.card,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <View style={styles.row}>
            <Text style={[styles.label, { color: theme.textPrimary }]}>
              Network
            </Text>
            <Pressable
              style={[
                styles.networkBadge,
                {
                backgroundColor:
                    network === "mainnet"
                      ? theme.networkMainnet
                      : theme.networkTestnet,
                  ...(isDemoMode ? styles.disabledNetworkBadge : null),
                },
              ]}
              onPress={isDemoMode ? undefined : toggleNetwork}
              disabled={isDemoMode}
            >
              <View style={styles.networkBadgeContent}>
                <Text style={styles.networkText}>
                  {network.toUpperCase()}
                  {isDemoMode ? " (Demo)" : ""}
                </Text>
                {isDemoMode ? (
                  <Ionicons
                    name="lock-closed"
                    size={12}
                    color="#fff"
                    style={styles.networkLockIcon}
                  />
                ) : null}
              </View>
            </Pressable>
          </View>

          <View style={styles.row}>
            <Text style={[styles.label, { color: theme.textPrimary }]}>
              Status
            </Text>
            <Text
              style={{
                color: connected ? theme.status.success : theme.status.error,
                fontWeight: "700",
              }}
            >
              {connected ? "Connected" : "Not Connected"}
            </Text>
          </View>

          {!isConnected ? (
            <View
              style={[
                styles.offlineAdvice,
                {
                  backgroundColor: theme.status.errorBg,
                  borderColor: theme.status.error,
                },
              ]}
            >
              <Ionicons
                name="information-circle-outline"
                size={18}
                color={theme.status.error}
              />
              <Text
                style={[
                  styles.offlineAdviceText,
                  { color: theme.status.error },
                ]}
              >
                Internet connection is required to link a wallet and run the
                first sync.
              </Text>
            </View>
          ) : null}

          {connected && publicKey ? (
            <Text style={[styles.address, { color: theme.textSecondary }]}>
              {publicKey}
            </Text>
          ) : null}

          {!connected ? (
            <Pressable
              style={[
                styles.primaryButton,
                { backgroundColor: theme.buttonPrimaryBg },
              ]}
              onPress={() => {
                void handleConnect();
              }}
            >
              <Text
                style={[styles.primaryButtonText, { color: theme.buttonPrimaryText }]}
              >
                Connect Wallet
              </Text>
            </Pressable>
          ) : (
            <>
              <Pressable
                style={[
                  styles.secondaryButton,
                  { borderColor: theme.buttonSecondaryBorder },
                ]}
                onPress={() => {
                  void revealSessionToken();
                }}
              >
                <Text
                  style={[
                    styles.secondaryButtonText,
                    { color: theme.buttonSecondaryText },
                  ]}
                >
                  Reveal Secure Session Token
                </Text>
              </Pressable>

              {sessionTokenPreview ? (
                <Text style={[styles.tokenPreview, { color: theme.textSecondary }]}>
                  Token: {sessionTokenPreview}
                </Text>
              ) : null}

              <Pressable
                style={[
                  styles.dangerButton,
                  { backgroundColor: theme.buttonDangerBg },
                ]}
                onPress={() => {
                  void handleDisconnect();
                }}
              >
                <Text
                  style={[styles.primaryButtonText, { color: theme.buttonDangerText }]}
                >
                  Disconnect
                </Text>
              </Pressable>
            </>
          )}
        </View>

        <Pressable style={styles.backButton} onPress={() => router.back()}>
          <Text style={[styles.backButtonText, { color: theme.textMuted }]}>
            Go Back
          </Text>
        </Pressable>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  content: {
    flex: 1,
    padding: 24,
  },
  title: {
    fontSize: 32,
    fontWeight: "700",
    marginTop: 40,
    marginBottom: 12,
  },
  subtitle: {
    fontSize: 16,
    lineHeight: 22,
    marginBottom: 24,
  },
  demoBanner: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 12,
    borderWidth: 1,
    gap: 8,
    marginBottom: 18,
  },
  demoBannerText: {
    flex: 1,
    fontSize: 14,
    fontWeight: "600",
    lineHeight: 20,
  },
  card: {
    borderRadius: 18,
    borderWidth: 1,
    padding: 18,
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 14,
  },
  label: {
    fontSize: 16,
    fontWeight: "700",
  },
  networkBadge: {
    borderRadius: 10,
    paddingVertical: 8,
    paddingHorizontal: 12,
  },
  disabledNetworkBadge: {
    opacity: 0.85,
  },
  networkBadgeContent: {
    flexDirection: "row",
    alignItems: "center",
  },
  networkText: {
    color: "#fff",
    fontWeight: "700",
  },
  networkLockIcon: {
    marginLeft: 4,
  },
  offlineAdvice: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderWidth: 1,
    borderRadius: 12,
    marginBottom: 16,
  },
  offlineAdviceText: {
    flex: 1,
    fontSize: 13,
    fontWeight: "500",
  },
  address: {
    fontSize: 12,
    marginBottom: 16,
  },
  primaryButton: {
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: "center",
  },
  dangerButton: {
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: "center",
    marginTop: 12,
  },
  primaryButtonText: {
    fontSize: 16,
    fontWeight: "700",
  },
  secondaryButton: {
    borderWidth: 1,
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: "center",
    marginTop: 12,
  },
  secondaryButtonText: {
    fontWeight: "700",
  },
  tokenPreview: {
    marginTop: 10,
    fontSize: 13,
  },
  backButton: {
    marginTop: 22,
    alignItems: "center",
  },
  backButtonText: {
    fontSize: 16,
  },
});
