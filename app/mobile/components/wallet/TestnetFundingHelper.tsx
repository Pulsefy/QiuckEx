import React, { useState, useEffect, useCallback } from "react";
import {
  StyleSheet,
  Text,
  View,
  Pressable,
  ActivityIndicator,
  Linking,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { openBrowserAsync, WebBrowserPresentationStyle } from "expo-web-browser";
import { useWalletContext } from "../../hooks/useWalletContext";
import { useTheme } from "../../src/theme/ThemeContext";

type ReadinessState = "loading" | "unfunded" | "low-balance" | "ready" | "error" | "disconnected" | "mainnet-only";

export default function TestnetFundingHelper() {
  const { theme } = useTheme();
  const { wallet } = useWalletContext();

  const [readiness, setReadiness] = useState<ReadinessState>("disconnected");
  const [balance, setBalance] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isFunding, setIsFunding] = useState(false);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [fundingError, setFundingError] = useState<string | null>(null);
  const [fundingSuccess, setFundingSuccess] = useState(false);

  const fetchBalance = useCallback(async () => {
    if (!wallet.connected || !wallet.publicKey) {
      setReadiness("disconnected");
      return;
    }

    if (wallet.network !== "testnet") {
      setReadiness("mainnet-only");
      return;
    }

    setIsLoading(true);
    setFetchError(null);

    try {
      const response = await fetch(
        `https://horizon-testnet.stellar.org/accounts/${wallet.publicKey}`
      );

      if (response.status === 404) {
        setBalance(0);
        setReadiness("unfunded");
      } else if (response.ok) {
        const data = await response.json();
        const nativeBalanceObj = data.balances?.find(
          (b: any) => b.asset_type === "native"
        );
        const balValue = nativeBalanceObj ? parseFloat(nativeBalanceObj.balance) : 0;
        setBalance(balValue);
        if (balValue >= 5.0) {
          setReadiness("ready");
        } else {
          setReadiness("low-balance");
        }
      } else {
        throw new Error(`Horizon API error (Status ${response.status})`);
      }
    } catch (err: any) {
      setFetchError(err.message || "Failed to fetch balance");
      setReadiness("error");
    } finally {
      setIsLoading(false);
    }
  }, [wallet.connected, wallet.publicKey, wallet.network]);

  useEffect(() => {
    setFundingSuccess(false);
    fetchBalance();
  }, [fetchBalance, wallet.publicKey]);

  const handleFund = async () => {
    if (!wallet.publicKey) return;
    setIsFunding(true);
    setFundingError(null);
    setFundingSuccess(false);

    try {
      const response = await fetch(
        `https://friendbot.stellar.org/?addr=${wallet.publicKey}`
      );
      if (response.ok) {
        setFundingSuccess(true);
        // Automatically refresh balance after successful funding
        await fetchBalance();
      } else {
        throw new Error(`Friendbot error (Status ${response.status})`);
      }
    } catch (err: any) {
      setFundingError(err.message || "Friendbot request failed. Faucet rate limits may apply.");
    } finally {
      setIsFunding(false);
    }
  };

  const openLink = async (url: string) => {
    try {
      if (process.env.EXPO_OS !== "web") {
        await openBrowserAsync(url, {
          presentationStyle: WebBrowserPresentationStyle.AUTOMATIC,
        });
      } else {
        await Linking.openURL(url);
      }
    } catch {
      // Fallback
      Linking.openURL(url).catch(() => {});
    }
  };

  // Only render if connected
  if (!wallet.connected) {
    return null;
  }

  // If on mainnet, show warning that helper is testnet only
  if (wallet.network !== "testnet") {
    return (
      <View
        style={[
          styles.container,
          { backgroundColor: theme.surface, borderColor: theme.border },
        ]}
      >
        <View style={styles.headerRow}>
          <Text style={[styles.title, { color: theme.textPrimary }]}>
            Testnet Wallet Funding Helper
          </Text>
          <View style={[styles.badge, { backgroundColor: theme.status.warningBg }]}>
            <Text style={[styles.badgeText, { color: theme.status.warning }]}>
              TESTNET ONLY
            </Text>
          </View>
        </View>
        <Text style={[styles.text, { color: theme.textSecondary }]}>
          Your wallet is currently connected to mainnet. This helper is only active when connected to the Stellar Testnet.
        </Text>
      </View>
    );
  }

  // Render readiness state
  const renderReadinessBadge = () => {
    if (isLoading) {
      return (
        <View style={[styles.statusBadge, { backgroundColor: theme.borderLight }]}>
          <ActivityIndicator size="small" color={theme.textMuted} style={styles.spinner} />
          <Text style={[styles.statusText, { color: theme.textSecondary }]}>
            Checking...
          </Text>
        </View>
      );
    }

    switch (readiness) {
      case "ready":
        return (
          <View style={[styles.statusBadge, { backgroundColor: theme.status.successBg }]}>
            <Ionicons name="checkmark-circle" size={16} color={theme.status.success} style={styles.badgeIcon} />
            <Text style={[styles.statusText, { color: theme.status.success }]}>
              Ready (Funded)
            </Text>
          </View>
        );
      case "low-balance":
        return (
          <View style={[styles.statusBadge, { backgroundColor: theme.status.warningBg }]}>
            <Ionicons name="alert-circle" size={16} color={theme.status.warning} style={styles.badgeIcon} />
            <Text style={[styles.statusText, { color: theme.status.warning }]}>
              Not Ready (Low Balance)
            </Text>
          </View>
        );
      case "unfunded":
        return (
          <View style={[styles.statusBadge, { backgroundColor: theme.status.errorBg }]}>
            <Ionicons name="alert-circle" size={16} color={theme.status.error} style={styles.badgeIcon} />
            <Text style={[styles.statusText, { color: theme.status.error }]}>
              Not Ready (Unfunded)
            </Text>
          </View>
        );
      case "error":
      default:
        return (
          <View style={[styles.statusBadge, { backgroundColor: theme.status.errorBg }]}>
            <Ionicons name="close-circle" size={16} color={theme.status.error} style={styles.badgeIcon} />
            <Text style={[styles.statusText, { color: theme.status.error }]}>
              Readiness Error
            </Text>
          </View>
        );
    }
  };

  return (
    <View
      style={[
        styles.container,
        { backgroundColor: theme.surface, borderColor: theme.border },
      ]}
    >
      {/* Header */}
      <View style={styles.headerRow}>
        <Text style={[styles.title, { color: theme.textPrimary }]}>
          Testnet Wallet Funding Helper
        </Text>
        <View style={[styles.badge, { backgroundColor: theme.status.infoBg }]}>
          <Text style={[styles.badgeText, { color: theme.status.info }]}>
            TESTNET ONLY
          </Text>
        </View>
      </View>

      <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
        Verify readiness for smart contracts and activate your testnet wallet.
      </Text>

      {/* Balance & Status Card */}
      <View style={[styles.statusCard, { backgroundColor: theme.background, borderColor: theme.borderLight }]}>
        <View style={styles.statusRow}>
          <Text style={[styles.statusLabel, { color: theme.textSecondary }]}>
            Balance:
          </Text>
          <Text style={[styles.balanceValue, { color: theme.textPrimary }]}>
            {balance !== null ? `${balance.toLocaleString()} XLM` : "—"}
          </Text>
        </View>

        <View style={styles.statusRow}>
          <Text style={[styles.statusLabel, { color: theme.textSecondary }]}>
            Readiness:
          </Text>
          {renderReadinessBadge()}
        </View>
      </View>

      {/* Warnings & Messages */}
      {readiness === "unfunded" && (
        <View style={[styles.adviceBox, { backgroundColor: theme.status.errorBg, borderColor: theme.status.error }]}>
          <Ionicons name="information-circle-outline" size={18} color={theme.status.error} />
          <Text style={[styles.adviceText, { color: theme.status.error }]}>
            This account is not yet on-chain on Testnet. Request Friendbot funds below or send at least 1.0 XLM to activate it.
          </Text>
        </View>
      )}

      {readiness === "low-balance" && (
        <View style={[styles.adviceBox, { backgroundColor: theme.status.warningBg, borderColor: theme.status.warning }]}>
          <Ionicons name="information-circle-outline" size={18} color={theme.status.warning} />
          <Text style={[styles.adviceText, { color: theme.status.warning }]}>
            Account active, but we recommend having at least 5.0 XLM to pay for Soroban footprint/gas fees and contract storage rent.
          </Text>
        </View>
      )}

      {fetchError && (
        <View style={[styles.adviceBox, { backgroundColor: theme.status.errorBg, borderColor: theme.status.error }]}>
          <Ionicons name="alert-circle-outline" size={18} color={theme.status.error} />
          <Text style={[styles.adviceText, { color: theme.status.error }]}>
            {fetchError}
          </Text>
        </View>
      )}

      {fundingError && (
        <View style={[styles.adviceBox, { backgroundColor: theme.status.errorBg, borderColor: theme.status.error }]}>
          <Ionicons name="alert-circle-outline" size={18} color={theme.status.error} />
          <Text style={[styles.adviceText, { color: theme.status.error }]}>
            {fundingError}
          </Text>
        </View>
      )}

      {fundingSuccess && (
        <View style={[styles.adviceBox, { backgroundColor: theme.status.successBg, borderColor: theme.status.success }]}>
          <Ionicons name="checkmark-circle-outline" size={18} color={theme.status.success} />
          <Text style={[styles.adviceText, { color: theme.status.success }]}>
            Faucet successfully funded this account!
          </Text>
        </View>
      )}

      {/* Guide Checklist */}
      <View style={styles.guideContainer}>
        <Text style={[styles.guideTitle, { color: theme.textPrimary }]}>
          Testnet Funding Guide
        </Text>

        <View style={styles.guideItem}>
          <Text style={[styles.guideBullet, { color: theme.textSecondary }]}>•</Text>
          <View style={styles.guideTextCol}>
            <Text style={[styles.guideLabel, { color: theme.textPrimary }]}>
              Activation (Min 1.0 XLM)
            </Text>
            <Text style={[styles.guideDesc, { color: theme.textMuted }]}>
              Required to register your address on the Stellar ledger.
            </Text>
          </View>
        </View>

        <View style={styles.guideItem}>
          <Text style={[styles.guideBullet, { color: theme.textSecondary }]}>•</Text>
          <View style={styles.guideTextCol}>
            <Text style={[styles.guideLabel, { color: theme.textPrimary }]}>
              Base Reserve (0.5 XLM per subentry)
            </Text>
            <Text style={[styles.guideDesc, { color: theme.textMuted }]}>
              Required for each trustline, offer, or signer you create.
            </Text>
          </View>
        </View>

        <View style={styles.guideItem}>
          <Text style={[styles.guideBullet, { color: theme.textSecondary }]}>•</Text>
          <View style={styles.guideTextCol}>
            <Text style={[styles.guideLabel, { color: theme.textPrimary }]}>
              Contract Interactions (Min 5.0 XLM recommended)
            </Text>
            <Text style={[styles.guideDesc, { color: theme.textMuted }]}>
              Covers gas (CPU/instructions) and storage rent for Soroban contract invocations.
            </Text>
          </View>
        </View>
      </View>

      {/* Action Buttons */}
      <View style={styles.actionRow}>
        <Pressable
          style={[
            styles.primaryButton,
            { backgroundColor: theme.buttonPrimaryBg },
            isFunding ? styles.buttonDisabled : null,
          ]}
          disabled={isFunding || isLoading}
          onPress={handleFund}
        >
          {isFunding ? (
            <ActivityIndicator size="small" color={theme.buttonPrimaryText} />
          ) : (
            <>
              <Ionicons name="water-outline" size={16} color={theme.buttonPrimaryText} style={styles.buttonIcon} />
              <Text style={[styles.primaryButtonText, { color: theme.buttonPrimaryText }]}>
                Fund via Faucet
              </Text>
            </>
          )}
        </Pressable>

        <Pressable
          style={[
            styles.secondaryButton,
            { borderColor: theme.buttonSecondaryBorder, backgroundColor: theme.buttonSecondaryBg },
            isLoading ? styles.buttonDisabled : null,
          ]}
          disabled={isLoading || isFunding}
          onPress={fetchBalance}
        >
          {isLoading ? (
            <ActivityIndicator size="small" color={theme.buttonSecondaryText} />
          ) : (
            <>
              <Ionicons name="refresh-outline" size={16} color={theme.buttonSecondaryText} style={styles.buttonIcon} />
              <Text style={[styles.secondaryButtonText, { color: theme.buttonSecondaryText }]}>
                Refresh
              </Text>
            </>
          )}
        </Pressable>
      </View>

      {/* Fallback External Links */}
      <View style={styles.linksRow}>
        <Pressable onPress={() => openLink("https://laboratory.stellar.org/#account-creator?network=testnet")}>
          <Text style={[styles.linkText, { color: theme.link }]}>
            Stellar Lab Faucet ↗
          </Text>
        </Pressable>
        <Text style={{ color: theme.textMuted }}>|</Text>
        <Pressable onPress={() => openLink("https://developers.stellar.org/docs/fundamentals-and-concepts/stellar-data-structures/accounts#minimum-balance")}>
          <Text style={[styles.linkText, { color: theme.link }]}>
            Stellar Funding Docs ↗
          </Text>
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    borderRadius: 18,
    borderWidth: 1,
    padding: 18,
    marginTop: 18,
    gap: 12,
  },
  headerRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  title: {
    fontSize: 18,
    fontWeight: "700",
    flex: 1,
  },
  badge: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 6,
  },
  badgeText: {
    fontSize: 10,
    fontWeight: "800",
  },
  subtitle: {
    fontSize: 13,
    lineHeight: 18,
    marginBottom: 4,
  },
  statusCard: {
    borderRadius: 12,
    borderWidth: 1,
    padding: 12,
    gap: 10,
  },
  statusRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  statusLabel: {
    fontSize: 14,
    fontWeight: "600",
  },
  balanceValue: {
    fontSize: 15,
    fontWeight: "700",
  },
  statusBadge: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 8,
  },
  spinner: {
    marginRight: 6,
  },
  badgeIcon: {
    marginRight: 6,
  },
  statusText: {
    fontSize: 12,
    fontWeight: "700",
  },
  adviceBox: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 8,
    padding: 10,
    borderWidth: 1,
    borderRadius: 10,
  },
  adviceText: {
    flex: 1,
    fontSize: 12,
    lineHeight: 16,
    fontWeight: "500",
  },
  guideContainer: {
    marginTop: 6,
    gap: 8,
  },
  guideTitle: {
    fontSize: 14,
    fontWeight: "700",
    marginBottom: 4,
  },
  guideItem: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 8,
  },
  guideBullet: {
    fontSize: 16,
    lineHeight: 18,
  },
  guideTextCol: {
    flex: 1,
    gap: 2,
  },
  guideLabel: {
    fontSize: 13,
    fontWeight: "600",
  },
  guideDesc: {
    fontSize: 11,
    lineHeight: 15,
  },
  actionRow: {
    flexDirection: "row",
    gap: 10,
    marginTop: 8,
  },
  primaryButton: {
    flex: 1,
    paddingVertical: 12,
    borderRadius: 10,
    alignItems: "center",
    justifyContent: "center",
    flexDirection: "row",
  },
  secondaryButton: {
    flex: 1,
    borderWidth: 1,
    paddingVertical: 12,
    borderRadius: 10,
    alignItems: "center",
    justifyContent: "center",
    flexDirection: "row",
  },
  buttonDisabled: {
    opacity: 0.6,
  },
  buttonIcon: {
    marginRight: 6,
  },
  primaryButtonText: {
    fontSize: 14,
    fontWeight: "700",
  },
  secondaryButtonText: {
    fontSize: 14,
    fontWeight: "700",
  },
  linksRow: {
    flexDirection: "row",
    justifyContent: "center",
    alignItems: "center",
    gap: 8,
    marginTop: 4,
  },
  linkText: {
    fontSize: 12,
    fontWeight: "600",
  },
  text: {
    fontSize: 14,
    lineHeight: 20,
  },
});
