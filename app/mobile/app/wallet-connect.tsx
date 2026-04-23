import { Ionicons } from "@expo/vector-icons";
import { useRouter, useLocalSearchParams } from "expo-router";
import React, { useState, useEffect } from "react";
import { Alert, Pressable, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import { useNetworkStatus } from "../hooks/use-network-status";
import { useSecurity } from "../hooks/use-security";
import { usePaymentListener } from "../hooks/usePaymentListener";
import { useOnboarding } from "../hooks/useOnboarding";
import { useTheme } from "../src/theme/ThemeContext";

type Network = "testnet" | "mainnet";

function generateMockSessionToken() {
  const random = Math.random().toString(36).slice(2, 14);
  return `qex_session_${random}`;
}

export default function WalletConnectScreen() {
  const router = useRouter();
  const params = useLocalSearchParams<{ demo?: string }>();
  const { theme } = useTheme();
  const { isConnected } = useNetworkStatus();
  const { trackOnboardingEvent } = useOnboarding();
  const {
    authenticateForSensitiveAction,
    clearSensitiveSessionToken,
    getSensitiveSessionToken,
    saveSensitiveSessionToken,
  } = useSecurity();

  const [connected, setConnected] = useState(false);
  const [network, setNetwork] = useState<Network>("testnet");
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [sessionTokenPreview, setSessionTokenPreview] = useState<string | null>(
    null,
  );
  const [isDemoMode, setIsDemoMode] = useState(false);

  useEffect(() => {
    const demo = params.demo === 'true';
    setIsDemoMode(demo);
    if (demo) {
      setNetwork("testnet");
    }
  }, [params.demo]);

  const handleConnect = async () => {
    const demoPublicKey = "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP";
    const realPublicKey = "GABCD1234MOCKPUBLICKEY5678XYZ";
    const mockPublicKey = isDemoMode ? demoPublicKey : realPublicKey;
    
    setConnected(true);
    setPublicKey(mockPublicKey);

    // Store wallet session token in secure storage, never in AsyncStorage/plain files.
    await saveSensitiveSessionToken(generateMockSessionToken());
    setSessionTokenPreview(null);

    // Track wallet connection
    trackOnboardingEvent('wallet_connected', {
      demo_mode: isDemoMode,
      network,
      timestamp: Date.now(),
    });
  };

  // Start polling for payments when publicKey is available
  usePaymentListener(publicKey ?? undefined);

  const handleDisconnect = async () => {
    setConnected(false);
    setPublicKey(null);
    setSessionTokenPreview(null);
    await clearSensitiveSessionToken();
  };

  const toggleNetwork = () => {
    setNetwork((prev: Network) => (prev === "testnet" ? "mainnet" : "testnet"));
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
      Alert.alert(
        "No token found",
        "No secure session token is currently stored.",
      );
      return;
    }

    setSessionTokenPreview(`${token.slice(0, 8)}...${token.slice(-4)}`);
  };

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <View style={styles.content}>
        <Text style={[styles.title, { color: theme.textPrimary }]}>Wallet Connection</Text>
        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
          Connect your Stellar wallet and protect sensitive wallet data with
          biometric security.
        </Text>

        {isDemoMode && (
          <View style={styles.demoBanner}>
            <Ionicons name="school-outline" size={20} color="#2563EB" />
            <Text style={styles.demoBannerText}>
              Demo Mode - Using testnet with practice funds
            </Text>
          </View>
        )}

        <View style={styles.card}>
          <View style={styles.row}>
            <Text style={styles.label}>Network</Text>
            <View style={[
              styles.networkBadge,
              network === "mainnet" ? styles.mainnet : styles.testnet,
              isDemoMode && styles.disabledNetworkBadge,
            ]}>
              <Text style={styles.networkText}>
                {network.toUpperCase()}
                {isDemoMode && ' (Demo)'}
              </Text>
              {isDemoMode && (
                <Ionicons name="lock-closed" size={12} color="#fff" style={{ marginLeft: 4 }} />
              )}
            </View>
        <View style={[styles.card, { backgroundColor: theme.surface, borderColor: theme.border }]}>
          <View style={styles.row}>
            <Text style={[styles.label, { color: theme.textPrimary }]}>Network</Text>
            <Pressable
              style={[
                styles.networkBadge,
                { backgroundColor: network === "mainnet" ? theme.networkMainnet : theme.networkTestnet },
              ]}
              onPress={toggleNetwork}
            >
              <Text style={styles.networkText}>{network.toUpperCase()}</Text>
            </Pressable>
          </View>

          <View style={styles.row}>
            <Text style={[styles.label, { color: theme.textPrimary }]}>Status</Text>
            <Text style={{ color: connected ? theme.status.success : theme.status.error, fontWeight: "700" }}>
              {connected ? "Connected" : "Not Connected"}
            </Text>
          </View>

          {!isConnected ? (
            <View style={[styles.offlineAdvice, { backgroundColor: theme.status.errorBg, borderColor: theme.status.error }]}>
              <Ionicons
                name="information-circle-outline"
                size={18}
                color={theme.status.error}
              />
              <Text style={[styles.offlineAdviceText, { color: theme.status.error }]}>
                Internet connection is required to link a new wallet.
              </Text>
            </View>
          ) : null}

          {connected && publicKey ? (
            <Text style={[styles.address, { color: theme.textSecondary }]}>{publicKey}</Text>
          ) : null}

          {!connected ? (
            <Pressable style={[styles.connectButton, { backgroundColor: theme.buttonPrimaryBg }]} onPress={handleConnect}>
              <Text style={[styles.buttonText, { color: theme.buttonPrimaryText }]}>Connect Wallet</Text>
            </Pressable>
          ) : (
            <>
              <Pressable
                style={[styles.secondaryButton, { borderColor: theme.buttonSecondaryBorder }]}
                onPress={revealSessionToken}
              >
                <Text style={[styles.secondaryButtonText, { color: theme.buttonSecondaryText }]}>
                  Reveal Secure Session Token
                </Text>
              </Pressable>
              {sessionTokenPreview ? (
                <Text style={[styles.tokenPreview, { color: theme.textSecondary }]}>
                  Token: {sessionTokenPreview}
                </Text>
              ) : null}

              <Pressable
                style={[styles.disconnectButton, { backgroundColor: theme.buttonDangerBg }]}
                onPress={handleDisconnect}
              >
                <Text style={[styles.buttonText, { color: theme.buttonDangerText }]}>Disconnect</Text>
              </Pressable>
            </>
          )}
        </View>

        <Pressable style={styles.backButton} onPress={() => router.back()}>
          <Text style={[styles.backButtonText, { color: theme.textMuted }]}>Go Back</Text>
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
    fontWeight: "bold",
    marginTop: 40,
    marginBottom: 12,
  },
  subtitle: {
    fontSize: 16,
    marginBottom: 28,
    lineHeight: 22,
  },
  card: {
    borderRadius: 16,
    borderWidth: 1,
    padding: 16,
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
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 8,
  },
  networkText: {
    color: "#fff", // Intentional: always white on coloured network badge
    fontWeight: "700",
  },
  offlineAdvice: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 8,
    marginBottom: 16,
    gap: 8,
    borderWidth: 1,
  },
  offlineAdviceText: {
    fontSize: 13,
    fontWeight: "500",
    flex: 1,
  },
  address: {
    fontSize: 12,
    marginBottom: 16,
  },
  connectButton: {
    padding: 16,
    borderRadius: 10,
    alignItems: "center",
  },
  disconnectButton: {
    padding: 16,
    borderRadius: 10,
    alignItems: "center",
    marginTop: 12,
  },
  secondaryButton: {
    borderWidth: 1,
    padding: 14,
    borderRadius: 10,
    alignItems: "center",
  },
  secondaryButtonText: {
    fontWeight: "700",
  },
  tokenPreview: {
    marginTop: 10,
    fontSize: 13,
  },
  buttonText: {
    fontWeight: "700",
    fontSize: 16,
  },
  backButton: {
    marginTop: 22,
    alignItems: "center",
  },
  backButtonText: {
    fontSize: 16,
  },
  demoBanner: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#EFF6FF",
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 8,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: "#BFDBFE",
  },
  demoBannerText: {
    color: "#1E40AF",
    fontSize: 14,
    fontWeight: "600",
    marginLeft: 8,
    flex: 1,
  },
  disabledNetworkBadge: {
    opacity: 0.7,
  },
});
