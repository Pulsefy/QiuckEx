import { Ionicons } from "@expo/vector-icons";
import { useLocalSearchParams, useRouter } from "expo-router";
import React, { useEffect, useState } from "react";
import {
    Alert,
    Pressable,
    ScrollView,
    StyleSheet,
    Text,
    View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import { useNotifications } from "../components/notifications/NotificationContext";
import { useNetworkStatus } from "../hooks/use-network-status";
import { useSecurity } from "../hooks/use-security";
import { useOnboarding } from "../hooks/useOnboarding";
import { SUPPORTED_WALLETS, useWalletContext } from "../hooks/useWalletContext";
import { useTheme } from "../src/theme/ThemeContext";
import type {
    StellarNetwork,
    WalletErrorCode,
    WalletType,
} from "../types/wallet";

// ── Error banner config ──────────────────────────────────────────────────────

const ERROR_BANNER: Record<
  WalletErrorCode,
  { icon: keyof typeof Ionicons.glyphMap; title: string }
> = {
  wallet_locked: {
    icon: "lock-closed-outline",
    title: "Wallet Locked",
  },
  wrong_network: {
    icon: "git-network-outline",
    title: "Wrong Network",
  },
  signature_rejected: {
    icon: "close-circle-outline",
    title: "Signature Rejected",
  },
  connection_failed: {
    icon: "alert-circle-outline",
    title: "Connection Failed",
  },
  session_expired: {
    icon: "time-outline",
    title: "Session Expired",
  },
  wallet_not_found: {
    icon: "search-outline",
    title: "Wallet Not Found",
  },
};

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
  } = useSecurity();

  const {
    wallet,
    connect,
    disconnect,
    switchAccount,
    switchNetwork,
    clearError,
  } = useWalletContext();

  const [sessionTokenPreview, setSessionTokenPreview] = useState<string | null>(
    null,
  );
  const [isDemoMode, setIsDemoMode] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [isDisconnecting, setIsDisconnecting] = useState(false);
  const [selectedWallet, setSelectedWallet] = useState<WalletType | null>(
    wallet.walletType ?? null,
  );

  // Sync demo mode from navigation params
  useEffect(() => {
    const nextDemoMode = params.demo === "true";
    setIsDemoMode(nextDemoMode);
    if (nextDemoMode) {
      setSelectedWallet("demo");
    }
  }, [params.demo]);

  // Auto-select the last-used wallet type once wallet context is hydrated
  useEffect(() => {
    if (!wallet.isRestoring && wallet.walletType && !selectedWallet) {
      setSelectedWallet(wallet.walletType);
    }
  }, [wallet.isRestoring, wallet.walletType, selectedWallet]);

  // ── Handlers ────────────────────────────────────────────────────────────

  const handleConnect = async () => {
    const walletType = isDemoMode ? "demo" : (selectedWallet ?? "demo");
    setIsConnecting(true);
    clearError();

    await connect(walletType, wallet.network as StellarNetwork);

    setIsConnecting(false);

    // Trigger sync + onboarding tracking regardless — syncNow is idempotent
    // and onboarding tracking should fire even if the connect eventually
    // resolved with an error (for analytics).
    await trackOnboardingEvent("wallet_connected", {
      wallet_type: walletType,
      network: wallet.network,
      timestamp: Date.now(),
    });
    await syncNow();
  };

  const handleDisconnect = async () => {
    setIsDisconnecting(true);
    setSessionTokenPreview(null);
    await disconnect();
    await clearSensitiveSessionToken();
    await syncNow();
    setIsDisconnecting(false);
  };

  const handleSwitchAccount = () => {
    // Fallback for platforms where Alert.prompt is not available (most RN platforms)
    if (typeof Alert.prompt !== "function") {
      Alert.alert(
        "Switch Account",
        "Account switching is available through your wallet extension. Change the active account in your wallet, then reconnect.",
        [
          { text: "Cancel", style: "cancel" },
          {
            text: "Reconnect",
            onPress: () => {
              void handleDisconnect();
            },
          },
        ],
      );
      return;
    }

    Alert.prompt?.("Switch Account", "Enter new public key", [
      { text: "Cancel", style: "cancel" },
      {
        text: "Switch",
        onPress: async (value?: string) => {
          if (value) {
            await switchAccount(value.trim());
            await syncNow();
          }
        },
      },
    ]);
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

  // ── Helpers ─────────────────────────────────────────────────────────────

  const errorConfig = wallet.error
    ? ERROR_BANNER[wallet.error.code as WalletErrorCode]
    : null;

  // ── Render ──────────────────────────────────────────────────────────────

  if (wallet.isRestoring) {
    return (
      <SafeAreaView
        style={[styles.container, { backgroundColor: theme.background }]}
      >
        <View style={styles.content}>
          <Text style={[styles.title, { color: theme.textPrimary }]}>
            Restoring session…
          </Text>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView
      style={[styles.container, { backgroundColor: theme.background }]}
    >
      <ScrollView
        contentContainerStyle={styles.scrollContent}
        showsVerticalScrollIndicator={false}
      >
        <Text style={[styles.title, { color: theme.textPrimary }]}>
          Wallet Connection
        </Text>
        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
          {wallet.connected
            ? "Your wallet is connected. You can switch accounts, change networks, or disconnect below."
            : "Connect a wallet once and QuickEx will remember it for next time."}
        </Text>

        {/* ── Demo banner ──────────────────────────────────────────────── */}
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

        {/* ── Error banner ─────────────────────────────────────────────── */}
        {wallet.error && errorConfig ? (
          <View
            style={[
              styles.errorBanner,
              {
                backgroundColor: theme.status.errorBg,
                borderColor: theme.status.error,
              },
            ]}
          >
            <Ionicons
              name={errorConfig.icon}
              size={20}
              color={theme.status.error}
            />
            <View style={styles.errorBannerCopy}>
              <Text
                style={[styles.errorBannerTitle, { color: theme.status.error }]}
              >
                {errorConfig.title}
              </Text>
              <Text
                style={[
                  styles.errorBannerMessage,
                  { color: theme.status.error },
                ]}
              >
                {wallet.error.message}
              </Text>
            </View>
            {wallet.error.recoverable ? (
              <Pressable onPress={clearError} style={styles.errorDismiss}>
                <Ionicons
                  name="close-outline"
                  size={18}
                  color={theme.status.error}
                />
              </Pressable>
            ) : null}
          </View>
        ) : null}

        {/* ── Connection card ──────────────────────────────────────────── */}
        <View
          style={[
            styles.card,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          {/* Network row */}
          <View style={styles.row}>
            <Text style={[styles.label, { color: theme.textPrimary }]}>
              Network
            </Text>
            <Pressable
              style={[
                styles.networkBadge,
                {
                  backgroundColor:
                    wallet.network === "mainnet"
                      ? theme.networkMainnet
                      : theme.networkTestnet,
                  ...(isDemoMode ? styles.disabledNetworkBadge : null),
                },
              ]}
              onPress={
                isDemoMode
                  ? undefined
                  : () =>
                      switchNetwork(
                        wallet.network === "testnet" ? "mainnet" : "testnet",
                      )
              }
              disabled={isDemoMode}
            >
              <View style={styles.networkBadgeContent}>
                <Text
                  style={[styles.networkText, { color: theme.qrBackground }]}
                >
                  {wallet.network.toUpperCase()}
                  {isDemoMode ? " (Demo)" : ""}
                </Text>
                {isDemoMode ? (
                  <Ionicons
                    name="lock-closed"
                    size={12}
                    color={theme.qrBackground}
                    style={styles.networkLockIcon}
                  />
                ) : null}
              </View>
            </Pressable>
          </View>

          {/* Status row */}
          <View style={styles.row}>
            <Text style={[styles.label, { color: theme.textPrimary }]}>
              Status
            </Text>
            <Text
              style={{
                color: wallet.connected
                  ? theme.status.success
                  : theme.status.error,
                fontWeight: "700",
              }}
            >
              {wallet.connected ? "Connected" : "Not Connected"}
            </Text>
          </View>

          {/* Wallet type row (when connected) */}
          {wallet.connected && wallet.walletType ? (
            <View style={styles.row}>
              <Text style={[styles.label, { color: theme.textPrimary }]}>
                Wallet
              </Text>
              <Text
                style={{
                  color: theme.textSecondary,
                  fontWeight: "600",
                  textTransform: "capitalize",
                }}
              >
                {SUPPORTED_WALLETS.find((w) => w.type === wallet.walletType)
                  ?.label ?? wallet.walletType}
              </Text>
            </View>
          ) : null}

          {/* Offline warning */}
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

          {/* Public key (when connected) */}
          {wallet.connected && wallet.publicKey ? (
            <Text style={[styles.address, { color: theme.textSecondary }]}>
              {wallet.publicKey}
            </Text>
          ) : null}

          {/* ── Not connected: wallet selector + connect button ────── */}
          {!wallet.connected ? (
            <>
              {/* Wallet picker */}
              {!isDemoMode ? (
                <View style={styles.walletPicker}>
                  <Text
                    style={[styles.pickerLabel, { color: theme.textSecondary }]}
                  >
                    Select a wallet provider
                  </Text>
                  {SUPPORTED_WALLETS.map((w) => (
                    <Pressable
                      key={w.type}
                      style={[
                        styles.walletOption,
                        {
                          backgroundColor:
                            selectedWallet === w.type
                              ? theme.chipActiveBg
                              : theme.background,
                          borderColor:
                            selectedWallet === w.type
                              ? theme.buttonPrimaryBg
                              : theme.border,
                        },
                      ]}
                      onPress={() => setSelectedWallet(w.type)}
                    >
                      <View style={styles.walletOptionCopy}>
                        <Text
                          style={[
                            styles.walletOptionLabel,
                            { color: theme.textPrimary },
                          ]}
                        >
                          {w.label}
                        </Text>
                        <Text
                          style={[
                            styles.walletOptionDesc,
                            { color: theme.textMuted },
                          ]}
                        >
                          {w.description}
                        </Text>
                      </View>
                      {selectedWallet === w.type ? (
                        <Ionicons
                          name="checkmark-circle"
                          size={22}
                          color={theme.buttonPrimaryBg}
                        />
                      ) : null}
                    </Pressable>
                  ))}
                </View>
              ) : null}

              <Pressable
                style={[
                  styles.primaryButton,
                  { backgroundColor: theme.buttonPrimaryBg },
                  isConnecting ? styles.buttonDisabled : null,
                ]}
                disabled={isConnecting || !isConnected}
                onPress={() => {
                  void handleConnect();
                }}
              >
                <Text
                  style={[
                    styles.primaryButtonText,
                    { color: theme.buttonPrimaryText },
                  ]}
                >
                  {isConnecting ? "Connecting…" : "Connect Wallet"}
                </Text>
              </Pressable>
            </>
          ) : (
            /* ── Connected: actions ─────────────────────────────────── */
            <>
              {/* Switch account */}
              <Pressable
                style={[
                  styles.secondaryButton,
                  { borderColor: theme.buttonSecondaryBorder },
                ]}
                onPress={handleSwitchAccount}
              >
                <Ionicons
                  name="swap-horizontal-outline"
                  size={18}
                  color={theme.buttonSecondaryText}
                  style={styles.actionIcon}
                />
                <Text
                  style={[
                    styles.secondaryButtonText,
                    { color: theme.buttonSecondaryText },
                  ]}
                >
                  Switch Account
                </Text>
              </Pressable>

              {/* Reveal session token */}
              <Pressable
                style={[
                  styles.secondaryButton,
                  { borderColor: theme.buttonSecondaryBorder },
                ]}
                onPress={() => {
                  void revealSessionToken();
                }}
              >
                <Ionicons
                  name="key-outline"
                  size={18}
                  color={theme.buttonSecondaryText}
                  style={styles.actionIcon}
                />
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
                <Text
                  style={[styles.tokenPreview, { color: theme.textSecondary }]}
                >
                  Token: {sessionTokenPreview}
                </Text>
              ) : null}

              {/* Disconnect */}
              <Pressable
                style={[
                  styles.dangerButton,
                  {
                    backgroundColor: theme.buttonDangerBg,
                    opacity: isDisconnecting ? 0.6 : 1,
                  },
                ]}
                disabled={isDisconnecting}
                onPress={() => {
                  void handleDisconnect();
                }}
              >
                <Ionicons
                  name="log-out-outline"
                  size={18}
                  color={theme.buttonDangerText}
                  style={styles.actionIcon}
                />
                <Text
                  style={[
                    styles.primaryButtonText,
                    { color: theme.buttonDangerText },
                  ]}
                >
                  {isDisconnecting ? "Disconnecting…" : "Disconnect"}
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
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  scrollContent: {
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
  errorBanner: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 12,
    borderWidth: 1,
    gap: 10,
    marginBottom: 18,
  },
  errorBannerCopy: {
    flex: 1,
    gap: 2,
  },
  errorBannerTitle: {
    fontSize: 14,
    fontWeight: "700",
  },
  errorBannerMessage: {
    fontSize: 13,
    lineHeight: 18,
  },
  errorDismiss: {
    padding: 4,
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
  walletPicker: {
    gap: 8,
    marginBottom: 16,
  },
  pickerLabel: {
    fontSize: 13,
    fontWeight: "600",
    marginBottom: 4,
  },
  walletOption: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    borderWidth: 1,
    borderRadius: 12,
    paddingVertical: 12,
    paddingHorizontal: 14,
  },
  walletOptionCopy: {
    flex: 1,
    gap: 2,
  },
  walletOptionLabel: {
    fontSize: 15,
    fontWeight: "600",
  },
  walletOptionDesc: {
    fontSize: 12,
    lineHeight: 16,
  },
  primaryButton: {
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: "center",
    flexDirection: "row",
    justifyContent: "center",
  },
  buttonDisabled: {
    opacity: 0.6,
  },
  dangerButton: {
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: "center",
    marginTop: 12,
    flexDirection: "row",
    justifyContent: "center",
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
    flexDirection: "row",
    justifyContent: "center",
  },
  actionIcon: {
    marginRight: 8,
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
