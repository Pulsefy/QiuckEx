import * as Linking from "expo-linking";
import { useLocalSearchParams, useRouter } from "expo-router";
import React from "react";
import { Alert, Pressable, StyleSheet, Text, View, ScrollView } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import { useSecurity } from "@/hooks/use-security";
import { useSwapOptions } from "@/hooks/use-swap-options";
import { SwapAssetSelector } from "@/components/swap-asset-selector";
import { SwapRateDetails } from "@/components/swap-rate-details";
import type { PathPreviewRow } from "@/services/link-metadata";
import { useTheme } from "../src/theme/ThemeContext";
import { useNetworkStatus } from "@/hooks/use-network-status";
import { saveContact } from "../services/contacts";
import { v4 as uuidv4 } from "uuid";

import { ActivityIndicator } from "react-native";
import { useContractRegistry } from "../hooks/useContractRegistry";
import { ErrorState } from "@/components/resilience/error-state";
import { useSession } from "../contexts/SessionContext";
import { resolveSwappableAssets } from "../services/swappable-assets";
import { NetworkMismatchGuard } from "@/components/wallet/NetworkMismatchGuard";
import { WalletSwitchHelpModal } from "@/components/wallet/WalletSwitchHelpModal";

export default function PaymentConfirmationScreen() {
  const router = useRouter();
  const [showHelpModal, setShowHelpModal] = React.useState(false);
  const { theme } = useTheme();
  const { isConnected } = useNetworkStatus();
  const { authenticateForSensitiveAction } = useSecurity();
  const backendUrl = process.env.EXPO_PUBLIC_API_URL || "https://api.quickex.com";
  const {
    isReady,
    error: registryError,
    status: registryStatus,
    lastUpdatedLabel,
    missingContracts,
    fetchSource: registryFetchSource,
    isRefreshing: registryRefreshing,
    refresh: refreshRegistry,
  } = useContractRegistry(["quickex"], backendUrl);
  const params = useLocalSearchParams<{
    username: string;
    amount: string;
    asset: string;
    memo?: string;
    privacy?: string;
  }>();

  const { username, amount, asset, memo, privacy } = params;
  const isPrivate = privacy === "true";
  const isValid = username && amount && asset;

  // Parse amount as a number for API
  const numAmount = parseFloat(amount || "0");

  // State for multi-asset swap
  const [selectedSourceAsset, setSelectedSourceAsset] = React.useState<string | null>(null);
  const [selectedSwapPath, setSelectedSwapPath] = React.useState<PathPreviewRow | null>(null);
  const [slippageTolerance, setSlippageTolerance] = React.useState(1.0); // 1.0% default

  // Swap asset whitelist sourced from the runtime config bootstrap, with a
  // conservative built-in default when config is unavailable (see
  // services/swappable-assets). This keeps the app in sync with the backend
  // without requiring an app store release.
  const { data: sessionData } = useSession();
  const swappableAssets = React.useMemo(
    () => resolveSwappableAssets(sessionData?.swappableAssets),
    [sessionData?.swappableAssets],
  );

  // Fetch swap options from backend (only if we have a valid destination asset)
  const {
    swapOptions,
    loading: swapLoading,
    error: swapError,
    timeRemaining,
    isExpired,
    refetch,
  } = useSwapOptions(username || "", numAmount, asset || "", swappableAssets);

  // Filter swap options to exclude the destination asset itself
  const availableSwapOptions = (swapOptions || []).filter(
    (opt) => opt.destinationAsset === asset && opt.sourceAsset !== asset
  );

  const handlePayWithWallet = async () => {
    if (isConnected === false) {
      Alert.alert(
        "Offline Mode",
        "You cannot send payments while offline. Please connect to the internet and try again."
      );
      return;
    }

    if (selectedSwapPath && isExpired) {
      Alert.alert(
        "Quote Expired",
        "The exchange rate has expired. Please refresh the quote before paying.",
        [{ text: "Refresh Now", onPress: () => void refetch() }, { text: "Cancel", style: "cancel" }]
      );
      return;
    }

    const authorized = await authenticateForSensitiveAction(
      "payment_authorization",
    );
    if (!authorized) {
      Alert.alert(
        "Authentication Required",
        "You must authenticate with biometrics or PIN before sending payment.",
      );
      return;
    }

    // Build the Stellar URI with multi-asset support
    let stellarUri: string;
    
    if (selectedSwapPath && selectedSourceAsset) {
      // Path payment: user selected a different source asset
      // Apply slippage tolerance to the source amount
      const sourceAmountBase = parseFloat(selectedSwapPath.sourceAmount);
      const sendMax = (sourceAmountBase * (1 + slippageTolerance / 100)).toFixed(7);
      const strippedSendMax = sendMax.replace(/\.?0+$/, '');
      
      stellarUri = `web+stellar:pay?destination=${username}&amount=${amount}&asset_code=${asset}${memo ? `&memo=${encodeURIComponent(memo)}` : ""}&sendAsset=${selectedSourceAsset}&sendAmount=${strippedSendMax}`;
    } else {
      // Direct payment with destination asset
      stellarUri = `web+stellar:pay?destination=${username}&amount=${amount}&asset_code=${asset}${memo ? `&memo=${encodeURIComponent(memo)}` : ""}`;
    }

    const canOpen = await Linking.canOpenURL(stellarUri);
    if (canOpen) {
      await Linking.openURL(stellarUri);
    } else {
      Alert.alert(
        "No Wallet Found",
        "Install a Stellar-compatible wallet to complete this payment.",
        [{ text: "OK" }],
      );
    }
  };

  const [savingContact, setSavingContact] = React.useState(false);
  
  if (registryStatus === "incompatible" || registryStatus === "unavailable") {
    const isMissingDefinition = missingContracts.length > 0;

    return (
      <SafeAreaView style={[styles.container, { backgroundColor: theme.background, justifyContent: 'center' }]}>
        <ErrorState
          title={isMissingDefinition ? "Contract definition missing" : "Contract registry unavailable"}
          message={
            isMissingDefinition
              ? `The registry does not include ${missingContracts.join(", ")}. Refresh contract metadata to recover from a stale or incompatible registry.`
              : registryError || "Contract metadata could not be loaded. Refresh the registry and try again."
          }
          onRetry={() => void refreshRegistry()}
          retryLabel={registryRefreshing ? "Refreshing..." : "Refresh Registry"}
        />
        <Pressable
          style={styles.secondaryBtn}
          onPress={() => router.back()}
          accessibilityLabel="Go back from contract registry error screen"
          accessibilityRole="button"
          accessibilityHint="Double-tap to navigate back to the previous screen"
        >
          <Text style={[styles.secondaryBtnText, { color: theme.textSecondary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Go Back</Text>
        </Pressable>
      </SafeAreaView>
    );
  }

  if (!isReady) {
    return (
      <SafeAreaView style={[styles.container, { backgroundColor: theme.background, justifyContent: 'center' }]}>
        <ActivityIndicator
          size="large"
          color={theme.primary}
          accessibilityLabel={`${registryRefreshing ? "Refreshing contract registry" : "Verifying secure contracts"} in progress`}
        />
        <Text style={{ color: theme.textSecondary, textAlign: 'center', marginTop: 10 }} accessibilityRole="status">
          {registryRefreshing ? "Refreshing contract registry..." : "Verifying secure contracts..."}
        </Text>
        <Text style={{ color: theme.textMuted, textAlign: 'center', marginTop: 6 }} accessibilityElementsHidden={true} importantForAccessibility="no">
          {lastUpdatedLabel}
        </Text>
      </SafeAreaView>
    );
  }

  if (!isValid) {
    return (
      <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
        <View style={[styles.content, { justifyContent: "center", flex: 1 }]}>
          <View
            style={[styles.errorCard, { backgroundColor: theme.status.errorBg }]}
            accessibilityLabel="Invalid Payment Link. Error: This payment link is missing required information. Please try scanning again or check the link."
            accessibilityRole="alert"
          >
            <Text style={[styles.errorIcon, { color: theme.status.error, backgroundColor: theme.status.errorBg }]} accessibilityElementsHidden={true} importantForAccessibility="no">!</Text>
            <Text style={[styles.errorTitle, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Invalid Payment Link</Text>
            <Text style={[styles.errorBody, { color: theme.textSecondary }]} accessibilityElementsHidden={true} importantForAccessibility="no">
              This payment link is missing required information. Please try
              scanning again or check the link.
            </Text>
          </View>
          <Pressable
            style={styles.secondaryBtn}
            onPress={() => router.replace("/")}
            accessibilityLabel="Go back to home screen from invalid payment link error"
            accessibilityRole="button"
            accessibilityHint="Double-tap to return to the home screen"
          >
            <Text style={[styles.secondaryBtnText, { color: theme.textSecondary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Go Back</Text>
          </Pressable>
        </View>
      </SafeAreaView>
    );
  }

  // Save Contact logic
  async function handleSaveContact() {
    if (isConnected === false) {
      Alert.alert(
        "Offline Mode",
        "Saving contacts is unavailable while offline."
      );
      return;
    }
    setSavingContact(true);
    try {
      await saveContact({
        id: uuidv4(),
        address: username,
        nickname: "",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
      Alert.alert("Contact saved!", "Recipient has been added to your contacts.");
    } catch (e) {
      Alert.alert("Failed to save contact");
    } finally {
      setSavingContact(false);
    }
  }

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <ScrollView style={styles.scrollContent} showsVerticalScrollIndicator={false}>
        <View style={styles.content}>
          <Text style={[styles.heading, { color: theme.textPrimary }]} accessibilityRole="header">Confirm Payment</Text>
          <Text
            style={[styles.subheading, { color: theme.textSecondary }]}
            accessibilityRole="status"
          >
            {isConnected === false ? "Read-only mode: payment is disabled" : "Review the details below before paying"}
          </Text>

          <View
            style={[
              styles.registryBanner,
              {
                backgroundColor:
                  registryStatus === "stale" ? theme.status.warningBg : theme.surface,
                borderColor:
                  registryStatus === "stale" ? theme.status.warning : theme.divider,
              },
            ]}
            accessibilityLabel={`Contract registry status: ${registryStatus === "stale" ? "stale, warning displayed." : registryFetchSource === "cache" ? "loaded from cache." : "verified, up to date."} ${lastUpdatedLabel}.`}
          >
            <View style={styles.registryTextGroup} accessibilityElementsHidden={true} importantForAccessibility="no">
              <Text style={[styles.registryTitle, { color: theme.textPrimary }]}>
                Registry {registryStatus === "stale" ? "stale" : registryFetchSource === "cache" ? "cached" : "verified"}
              </Text>
              <Text style={[styles.registryMeta, { color: theme.textSecondary }]}>
                {lastUpdatedLabel}
              </Text>
            </View>
            <Pressable
              style={[
                styles.registryRefreshButton,
                { borderColor: theme.divider },
                registryRefreshing && { opacity: 0.6 },
              ]}
              onPress={() => void refreshRegistry()}
              disabled={registryRefreshing}
              accessibilityLabel={`Refresh contract registry. ${registryRefreshing ? 'Currently refreshing, button disabled.' : 'Tap to refresh registry status.'}`}
              accessibilityRole="button"
              accessibilityState={{ disabled: registryRefreshing }}
            >
              <Text style={[styles.registryRefreshText, { color: theme.buttonPrimaryBg }]} accessibilityElementsHidden={true} importantForAccessibility="no">
                {registryRefreshing ? "Refreshing" : "Refresh"}
              </Text>
            </Pressable>
          </View>

          <View style={[styles.card, { backgroundColor: theme.surface }]}>
            <Row label="Recipient" value={`@${username}`} />
            <View style={[styles.divider, { backgroundColor: theme.divider }]} accessibilityElementsHidden={true} importantForAccessibility="no" />
            <Row label="Amount" value={`${amount} ${asset}`} highlight />
            {memo ? (
              <>
                <View style={[styles.divider, { backgroundColor: theme.divider }]} accessibilityElementsHidden={true} importantForAccessibility="no" />
                <Row label="Memo" value={memo} />
              </>
            ) : null}
            {isPrivate ? (
              <>
                <View style={[styles.divider, { backgroundColor: theme.divider }]} accessibilityElementsHidden={true} importantForAccessibility="no" />
                <Row label="Privacy" value="X-Ray enabled" />
              </>
            ) : null}
          </View>

          {/* Multi-Asset Swap Section */}
          {(availableSwapOptions.length > 0 || swapError) && (
            <View style={styles.swapSection}>
              {swapError ? (
                <View
                  style={[styles.errorBanner, { backgroundColor: theme.status.errorBg }]}
                  accessibilityLabel={`Swap error alert: ${swapError}. ${swapError.includes('Liquidity') ? 'Tap Retry Search button to retry liquidity lookup.' : ''}`}
                  accessibilityRole="alert"
                >
                  <Text style={[styles.errorBannerText, { color: theme.status.error }]} accessibilityElementsHidden={true} importantForAccessibility="no">⚠ {swapError}</Text>
                  {swapError.includes('Liquidity') && (
                    <Pressable
                      style={{ marginTop: 8 }}
                      onPress={() => void refetch()}
                      accessibilityLabel="Retry swap search. Liquidity error recovery."
                      accessibilityRole="button"
                    >
                      <Text
                        style={{ color: theme.buttonPrimaryBg, fontWeight: '700', fontSize: 13 }}
                        accessibilityElementsHidden={true}
                        importantForAccessibility="no"
                      >Retry Search</Text>
                    </Pressable>
                  )}
                </View>
              ) : (
                <SwapAssetSelector
                  swapOptions={availableSwapOptions}
                  destinationAsset={asset || ""}
                  destinationAmount={amount || "0"}
                  selectedSourceAsset={selectedSourceAsset}
                  onSelectSourceAsset={(sourceAsset, path) => {
                    setSelectedSourceAsset(sourceAsset);
                    setSelectedSwapPath(path);
                  }}
                  loading={swapLoading}
                />
              )}
            </View>
          )}

          {/* Show cost comparison if swap is selected */}
          {selectedSwapPath && (
            <>
              <View style={[styles.costComparisonCard, { backgroundColor: theme.surface }]}>
                <Text style={[styles.costComparisonTitle, { color: theme.textPrimary }]} accessibilityRole="header">Payment Summary</Text>
                <View
                  style={styles.costRow}
                  accessibilityLabel={`You pay: ${selectedSwapPath.sourceAmount} ${selectedSwapPath.sourceAsset}. Total source amount before fees.`}
                >
                  <Text style={[styles.costLabel, { color: theme.textSecondary }]} accessibilityElementsHidden={true} importantForAccessibility="no">You pay:</Text>
                  <Text style={[styles.costValue, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">
                    {selectedSwapPath.sourceAmount} {selectedSwapPath.sourceAsset}
                  </Text>
                </View>
                <View style={[styles.costDivider, { backgroundColor: theme.divider }]} accessibilityElementsHidden={true} importantForAccessibility="no" />
                <View
                  style={styles.costRow}
                  accessibilityLabel={`Exchange rate: ${selectedSwapPath.rateDescription}.`}
                >
                  <Text style={[styles.costLabel, { color: theme.textSecondary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Exchange rate:</Text>
                  <Text style={[styles.costValue, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">{selectedSwapPath.rateDescription}</Text>
                </View>
                {selectedSwapPath.hopCount > 0 && (
                  <>
                    <View style={[styles.costDivider, { backgroundColor: theme.divider }]} accessibilityElementsHidden={true} importantForAccessibility="no" />
                    <View
                      style={styles.costRow}
                      accessibilityLabel={`Payment route: ${selectedSwapPath.hopCount === 1 ? "1 intermediary hop." : `${selectedSwapPath.hopCount} intermediary hops.`} Via Stellar path payment.`}
                    >
                      <Text style={[styles.costLabel, { color: theme.textSecondary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Path:</Text>
                      <Text style={[styles.costValue, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">
                        {selectedSwapPath.hopCount === 1
                          ? "1 intermediary"
                          : `${selectedSwapPath.hopCount} intermediaries`}
                      </Text>
                    </View>
                  </>
                )}
              </View>

              {/* Show detailed swap rate information with slippage warning */}
              <SwapRateDetails
                swapPath={selectedSwapPath}
                destinationAsset={asset || ""}
                destinationAmount={amount || "0"}
                timeRemaining={timeRemaining}
                isExpired={isExpired}
                onRefresh={() => void refetch()}
                slippageTolerance={slippageTolerance}
                onSlippageChange={setSlippageTolerance}
              />
            </>
          )}
        </View>
      </ScrollView>

      <View style={styles.actions}>
        <NetworkMismatchGuard onBlocked={() => setShowHelpModal(true)}>
          <Pressable
            style={[
              styles.primaryBtn,
              { backgroundColor: theme.buttonPrimaryBg },
              isConnected === false && { opacity: 0.5 }
            ]}
            onPress={handlePayWithWallet}
            disabled={isConnected === false}
            accessibilityLabel={
              isConnected === false
                ? "Payment is disabled. You are currently offline. Connect to the internet to pay."
                : `Pay ${amount} ${asset}${isPrivate ? ' with X-Ray privacy shield' : ''} to @${username} using your connected Stellar wallet.`
            }
            accessibilityRole="button"
            accessibilityState={{ disabled: isConnected === false }}
            accessibilityHint="Double-tap to authenticate and launch your wallet with the payment URI"
          >
            <Text style={[styles.primaryBtnText, { color: theme.buttonPrimaryText }]} accessibilityElementsHidden={true} importantForAccessibility="no">
              {isConnected === false ? "Offline: Payment Disabled" : "Pay with Wallet"}
            </Text>
          </Pressable>
        </NetworkMismatchGuard>
        <Pressable
          style={styles.secondaryBtn}
          onPress={() => router.replace("/")}
          accessibilityLabel="Cancel this payment and return to the home screen"
          accessibilityRole="button"
          accessibilityHint="Double-tap to go back to the home screen without paying"
        >
          <Text style={[styles.secondaryBtnText, { color: theme.textSecondary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Cancel</Text>
        </Pressable>
        <Pressable
          style={[styles.secondaryBtn, { marginTop: 8 }]}
          onPress={handleSaveContact}
          disabled={savingContact || isConnected === false}
          accessibilityLabel={
            savingContact
              ? `Saving recipient @${username} to your contacts. Please wait...`
              : isConnected === false
                ? "Save recipient as contact is disabled while offline. Connect to internet to save."
                : `Save recipient @${username} to your address book contacts.`
          }
          accessibilityRole="button"
          accessibilityState={{ disabled: savingContact || isConnected === false }}
        >
          <Text style={[styles.secondaryBtnText, { color: theme.textSecondary }, isConnected === false && { opacity: 0.5 }]} accessibilityElementsHidden={true} importantForAccessibility="no">
            {savingContact ? "Saving..." : "Save Recipient as Contact"}
          </Text>
        </Pressable>
      </View>
    </SafeAreaView>
  );
}

function Row({
  label,
  value,
  highlight,
}: {
  label: string;
  value: string;
  highlight?: boolean;
}) {
  const { theme } = useTheme();
  return (
    <View
      style={styles.row}
      accessibilityLabel={`${label}: ${value}.${highlight ? ' Important value highlighted.' : ''}`}
    >
      <Text style={[styles.rowLabel, { color: theme.textSecondary }]} accessibilityElementsHidden={true} importantForAccessibility="no">{label}</Text>
      <Text style={[styles.rowValue, { color: theme.textPrimary }, highlight && styles.rowValueHighlight]} accessibilityElementsHidden={true} importantForAccessibility="no">
        {value}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  scrollContent: {
    flex: 1,
  },
  content: {
    padding: 24,
    paddingBottom: 32,
  },
  heading: {
    fontSize: 32,
    fontWeight: "bold",
    marginBottom: 4,
  },
  subheading: {
    fontSize: 16,
    marginBottom: 32,
  },
  card: {
    borderRadius: 16,
    padding: 20,
    marginBottom: 20,
  },
  registryBanner: {
    alignItems: "center",
    borderRadius: 12,
    borderWidth: 1,
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 20,
    paddingHorizontal: 14,
    paddingVertical: 12,
  },
  registryTextGroup: {
    flex: 1,
    paddingRight: 12,
  },
  registryTitle: {
    fontSize: 14,
    fontWeight: "700",
    marginBottom: 2,
  },
  registryMeta: {
    fontSize: 12,
  },
  registryRefreshButton: {
    borderRadius: 8,
    borderWidth: 1,
    minWidth: 86,
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  registryRefreshText: {
    fontSize: 13,
    fontWeight: "700",
    textAlign: "center",
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 14,
    minHeight: 52,
  },
  rowLabel: { fontSize: 15 },
  rowValue: {
    fontSize: 16,
    fontWeight: "500",
    flexShrink: 1,
    textAlign: "right",
  },
  rowValueHighlight: { fontSize: 20, fontWeight: "700" },
  divider: { height: 1 },
  swapSection: {
    marginBottom: 20,
  },
  errorBanner: {
    borderRadius: 12,
    padding: 12,
    marginBottom: 16,
  },
  errorBannerText: {
    fontSize: 14,
    fontWeight: "500",
  },
  costComparisonCard: {
    borderRadius: 16,
    padding: 16,
    marginBottom: 20,
  },
  costComparisonTitle: {
    fontSize: 16,
    fontWeight: "700",
    marginBottom: 12,
  },
  costRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 10,
  },
  costLabel: {
    fontSize: 14,
  },
  costValue: {
    fontSize: 14,
    fontWeight: "600",
  },
  costDivider: {
    height: 1,
    marginVertical: 8,
  },
  actions: { 
    gap: 12,
    padding: 24,
    paddingTop: 12,
  },
  primaryBtn: {
    minHeight: 56,
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: "center",
    justifyContent: "center",
  },
  primaryBtnText: { fontSize: 18, fontWeight: "700" },
  secondaryBtn: {
    minHeight: 48,
    paddingVertical: 14,
    alignItems: "center",
    justifyContent: "center",
  },
  secondaryBtnText: { fontSize: 16, fontWeight: "500" },
  errorCard: {
    borderRadius: 16,
    padding: 32,
    alignItems: "center",
    marginBottom: 24,
  },
  errorIcon: {
    fontSize: 36,
    fontWeight: "bold",
    width: 56,
    height: 56,
    lineHeight: 56,
    borderRadius: 28,
    textAlign: "center",
    marginBottom: 16,
    overflow: "hidden",
  },
  errorTitle: {
    fontSize: 22,
    fontWeight: "700",
    marginBottom: 8,
  },
  errorBody: {
    fontSize: 15,
    textAlign: "center",
    lineHeight: 22,
  },
});
