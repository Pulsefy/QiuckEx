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

// List of assets to attempt swaps from (hardcoded whitelist matching backend)
const SWAPPABLE_ASSETS = ["XLM", "USDC", "AQUA", "yXLM"];

export default function PaymentConfirmationScreen() {
  const router = useRouter();
  const { authenticateForSensitiveAction } = useSecurity();
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

  // Fetch swap options from backend (only if we have a valid destination asset)
  const {
    swapOptions,
    loading: swapLoading,
    error: swapError,
  } = useSwapOptions(username || "", numAmount, asset || "", SWAPPABLE_ASSETS);

  // Filter swap options to exclude the destination asset itself
  const availableSwapOptions = (swapOptions || []).filter(
    (opt) => opt.destinationAsset === asset && opt.sourceAsset !== asset
  );

  const handlePayWithWallet = async () => {
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
      // The Stellar URI would delegate to the wallet to handle the path payment
      // Format: web+stellar:pay?destination=...&amount=...&asset_code=...&sendAsset=...
      const strippedSendAmount = selectedSwapPath.sourceAmount.replace(/\.?0+$/, '');
      stellarUri = `web+stellar:pay?destination=${username}&amount=${amount}&asset_code=${asset}${memo ? `&memo=${encodeURIComponent(memo)}` : ""}&sendAsset=${selectedSourceAsset}&sendAmount=${strippedSendAmount}`;
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

  if (!isValid) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={[styles.content, { justifyContent: "center", flex: 1 }]}>
          <View style={styles.errorCard}>
            <Text style={styles.errorIcon}>!</Text>
            <Text style={styles.errorTitle}>Invalid Payment Link</Text>
            <Text style={styles.errorBody}>
              This payment link is missing required information. Please try
              scanning again or check the link.
            </Text>
          </View>
          <Pressable
            style={styles.secondaryBtn}
            onPress={() => router.replace("/")}
          >
            <Text style={styles.secondaryBtnText}>Go Back</Text>
          </Pressable>
        </View>
      </SafeAreaView>
    );
  }

  // Save Contact logic
  const [savingContact, setSavingContact] = React.useState(false);
  const { saveContact } = require("../services/contacts");
  const { v4: uuidv4 } = require("uuid");
  async function handleSaveContact() {
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
    <SafeAreaView style={styles.container}>
      <ScrollView style={styles.scrollContent} showsVerticalScrollIndicator={false}>
        <View style={styles.content}>
          <Text style={styles.heading}>Confirm Payment</Text>
          <Text style={styles.subheading}>
            Review the details below before paying
          </Text>

          <View style={styles.card}>
            <Row label="Recipient" value={`@${username}`} />
            <View style={styles.divider} />
            <Row label="Amount" value={`${amount} ${asset}`} highlight />
            {memo ? (
              <>
                <View style={styles.divider} />
                <Row label="Memo" value={memo} />
              </>
            ) : null}
            {isPrivate ? (
              <>
                <View style={styles.divider} />
                <Row label="Privacy" value="X-Ray enabled" />
              </>
            ) : null}
          </View>

          {/* Multi-Asset Swap Section */}
          {availableSwapOptions && availableSwapOptions.length > 0 && (
            <View style={styles.swapSection}>
              {swapError ? (
                <View style={styles.errorBanner}>
                  <Text style={styles.errorBannerText}>⚠ {swapError}</Text>
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
              <View style={styles.costComparisonCard}>
                <Text style={styles.costComparisonTitle}>Payment Summary</Text>
                <View style={styles.costRow}>
                  <Text style={styles.costLabel}>You pay:</Text>
                  <Text style={styles.costValue}>
                    {selectedSwapPath.sourceAmount} {selectedSwapPath.sourceAsset}
                  </Text>
                </View>
                <View style={styles.costDivider} />
                <View style={styles.costRow}>
                  <Text style={styles.costLabel}>Exchange rate:</Text>
                  <Text style={styles.costValue}>{selectedSwapPath.rateDescription}</Text>
                </View>
                {selectedSwapPath.hopCount > 0 && (
                  <>
                    <View style={styles.costDivider} />
                    <View style={styles.costRow}>
                      <Text style={styles.costLabel}>Path:</Text>
                      <Text style={styles.costValue}>
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
              />
            </>
          )}
        </View>
      </ScrollView>

      <View style={styles.actions}>
        <Pressable style={styles.primaryBtn} onPress={handlePayWithWallet}>
          <Text style={styles.primaryBtnText}>Pay with Wallet</Text>
        </Pressable>
        <Pressable
          style={styles.secondaryBtn}
          onPress={() => router.replace("/")}
        >
          <Text style={styles.secondaryBtnText}>Cancel</Text>
        </Pressable>
        <Pressable
          style={[styles.secondaryBtn, { marginTop: 8 }]}
          onPress={handleSaveContact}
          disabled={savingContact}
        >
          <Text style={styles.secondaryBtnText}>
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
  return (
    <View style={styles.row}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={[styles.rowValue, highlight && styles.rowValueHighlight]}>
        {value}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#fff" },
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
    color: "#000",
    marginBottom: 4,
  },
  subheading: {
    fontSize: 16,
    color: "#888",
    marginBottom: 32,
  },
  card: {
    backgroundColor: "#F5F5F5",
    borderRadius: 16,
    padding: 20,
    marginBottom: 20,
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 14,
  },
  rowLabel: { fontSize: 15, color: "#888" },
  rowValue: {
    fontSize: 16,
    fontWeight: "500",
    color: "#222",
    flexShrink: 1,
    textAlign: "right",
  },
  rowValueHighlight: { fontSize: 20, fontWeight: "700", color: "#000" },
  divider: { height: 1, backgroundColor: "#E5E5E5" },
  swapSection: {
    marginBottom: 20,
  },
  errorBanner: {
    backgroundColor: "#FFF3F3",
    borderRadius: 12,
    padding: 12,
    marginBottom: 16,
  },
  errorBannerText: {
    fontSize: 14,
    color: "#FF3B30",
    fontWeight: "500",
  },
  costComparisonCard: {
    backgroundColor: "#F5F5F5",
    borderRadius: 16,
    padding: 16,
    marginBottom: 20,
  },
  costComparisonTitle: {
    fontSize: 16,
    fontWeight: "700",
    color: "#000",
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
    color: "#888",
  },
  costValue: {
    fontSize: 14,
    fontWeight: "600",
    color: "#000",
  },
  costDivider: {
    height: 1,
    backgroundColor: "#E5E5E5",
    marginVertical: 8,
  },
  actions: { 
    gap: 12,
    padding: 24,
    paddingTop: 12,
  },
  primaryBtn: {
    backgroundColor: "#000",
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: "center",
  },
  primaryBtnText: { color: "#fff", fontSize: 18, fontWeight: "700" },
  secondaryBtn: {
    paddingVertical: 14,
    alignItems: "center",
  },
  secondaryBtnText: { color: "#888", fontSize: 16, fontWeight: "500" },
  errorCard: {
    backgroundColor: "#FFF3F3",
    borderRadius: 16,
    padding: 32,
    alignItems: "center",
    marginBottom: 24,
  },
  errorIcon: {
    fontSize: 36,
    fontWeight: "bold",
    color: "#FF3B30",
    backgroundColor: "#FFE5E5",
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
    color: "#222",
    marginBottom: 8,
  },
  errorBody: {
    fontSize: 15,
    color: "#888",
    textAlign: "center",
    lineHeight: 22,
  },
});
