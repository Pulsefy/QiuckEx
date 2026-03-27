import { Ionicons } from "@expo/vector-icons";
import { useRouter } from "expo-router";
import React, { useState } from "react";
import { Alert, Pressable, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import { useNetworkStatus } from "../hooks/use-network-status";
import { useSecurity } from "../hooks/use-security";
import { usePaymentListener } from "../hooks/usePaymentListener";

type Network = "testnet" | "mainnet";

function generateMockSessionToken() {
  const random = Math.random().toString(36).slice(2, 14);
  return `qex_session_${random}`;
}

export default function WalletConnectScreen() {
  const router = useRouter();
  const { isConnected } = useNetworkStatus();
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

  const handleConnect = async () => {
    const mockPublicKey = "GABCD1234MOCKPUBLICKEY5678XYZ";
    setConnected(true);
    setPublicKey(mockPublicKey);

    // Store wallet session token in secure storage, never in AsyncStorage/plain files.
    await saveSensitiveSessionToken(generateMockSessionToken());
    setSessionTokenPreview(null);
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
    setNetwork((prev) => (prev === "testnet" ? "mainnet" : "testnet"));
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
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.title}>Wallet Connection</Text>
        <Text style={styles.subtitle}>
          Connect your Stellar wallet and protect sensitive wallet data with
          biometric security.
        </Text>

        <View style={styles.card}>
          <View style={styles.row}>
            <Text style={styles.label}>Network</Text>
            <Pressable
              style={[
                styles.networkBadge,
                network === "mainnet" ? styles.mainnet : styles.testnet,
              ]}
              onPress={toggleNetwork}
            >
              <Text style={styles.networkText}>{network.toUpperCase()}</Text>
            </Pressable>
          </View>

          <View style={styles.row}>
            <Text style={styles.label}>Status</Text>
            <Text style={connected ? styles.connected : styles.disconnected}>
              {connected ? "Connected" : "Not Connected"}
            </Text>
          </View>

          {!isConnected ? (
            <View style={styles.offlineAdvice}>
              <Ionicons
                name="information-circle-outline"
                size={18}
                color="#991B1B"
              />
              <Text style={styles.offlineAdviceText}>
                Internet connection is required to link a new wallet.
              </Text>
            </View>
          ) : null}

          {connected && publicKey ? (
            <Text style={styles.address}>{publicKey}</Text>
          ) : null}

          {!connected ? (
            <Pressable style={styles.connectButton} onPress={handleConnect}>
              <Text style={styles.buttonText}>Connect Wallet</Text>
            </Pressable>
          ) : (
            <>
              <Pressable
                style={styles.secondaryButton}
                onPress={revealSessionToken}
              >
                <Text style={styles.secondaryButtonText}>
                  Reveal Secure Session Token
                </Text>
              </Pressable>
              {sessionTokenPreview ? (
                <Text style={styles.tokenPreview}>
                  Token: {sessionTokenPreview}
                </Text>
              ) : null}

              <Pressable
                style={styles.disconnectButton}
                onPress={handleDisconnect}
              >
                <Text style={styles.buttonText}>Disconnect</Text>
              </Pressable>
            </>
          )}
        </View>

        <Pressable style={styles.backButton} onPress={() => router.back()}>
          <Text style={styles.backButtonText}>Go Back</Text>
        </Pressable>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#fff",
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
    color: "#111827",
  },
  subtitle: {
    fontSize: 16,
    color: "#6B7280",
    marginBottom: 28,
    lineHeight: 22,
  },
  card: {
    backgroundColor: "#F9FAFB",
    borderRadius: 16,
    borderWidth: 1,
    borderColor: "#E5E7EB",
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
    color: "#111827",
  },
  networkBadge: {
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 8,
  },
  mainnet: {
    backgroundColor: "#10B981",
  },
  testnet: {
    backgroundColor: "#F59E0B",
  },
  networkText: {
    color: "#fff",
    fontWeight: "700",
  },
  connected: {
    color: "#10B981",
    fontWeight: "700",
  },
  disconnected: {
    color: "#EF4444",
    fontWeight: "700",
  },
  offlineAdvice: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#FEF2F2",
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 8,
    marginBottom: 16,
    gap: 8,
    borderWidth: 1,
    borderColor: "#FECACA",
  },
  offlineAdviceText: {
    color: "#991B1B",
    fontSize: 13,
    fontWeight: "500",
    flex: 1,
  },
  address: {
    fontSize: 12,
    color: "#374151",
    marginBottom: 16,
  },
  connectButton: {
    backgroundColor: "#111827",
    padding: 16,
    borderRadius: 10,
    alignItems: "center",
  },
  disconnectButton: {
    backgroundColor: "#EF4444",
    padding: 16,
    borderRadius: 10,
    alignItems: "center",
    marginTop: 12,
  },
  secondaryButton: {
    borderColor: "#111827",
    borderWidth: 1,
    padding: 14,
    borderRadius: 10,
    alignItems: "center",
  },
  secondaryButtonText: {
    color: "#111827",
    fontWeight: "700",
  },
  tokenPreview: {
    marginTop: 10,
    fontSize: 13,
    color: "#4B5563",
  },
  buttonText: {
    color: "#fff",
    fontWeight: "700",
    fontSize: 16,
  },
  backButton: {
    marginTop: 22,
    alignItems: "center",
  },
  backButtonText: {
    color: "#6B7280",
    fontSize: 16,
  },
});
