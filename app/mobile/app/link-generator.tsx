import React, { useState, useEffect, useMemo, useCallback } from "react";
import {
  View,
  Text,
  StyleSheet,
  TextInput,
  TouchableOpacity,
  ScrollView,
  ActivityIndicator,
  Share,
  useColorScheme,
  Alert,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import Constants from "expo-constants";
import * as Clipboard from "expo-clipboard";
import { StrKey } from "@stellar/stellar-base";

import { QRPreviewModal } from "../components/QRPreviewModal";

const API_BASE_URL =
  (Constants.expoConfig?.extra?.apiUrl as string | undefined) ??
  process.env["EXPO_PUBLIC_API_URL"] ??
  "http://localhost:3000";

type VerifiedAsset = {
  code: string;
  type: string;
  issuer: string | null;
  verified: boolean;
  decimals: number;
};

type LinkMetadataSuccess = {
  success: true;
  data: {
    canonical: string;
    amount: string;
    asset: string;
    destination?: string | null;
    memo: string | null;
    metadata?: Record<string, unknown>;
  };
};

export default function LinkGeneratorScreen() {
  const colorScheme = useColorScheme();
  const isDark = colorScheme === "dark";

  const [form, setForm] = useState({
    amount: "",
    destination: "",
    memo: "",
  });

  const [recipientAssetCode, setRecipientAssetCode] = useState("USDC");
  const [verifiedAssets, setVerifiedAssets] = useState<VerifiedAsset[]>([]);
  const [assetsLoading, setAssetsLoading] = useState(true);

  const [loading, setLoading] = useState(false);
  const [canonicalData, setCanonicalData] = useState<string | null>(null);

  const [qrModalVisible, setQrModalVisible] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setAssetsLoading(true);
      try {
        const res = await fetch(`${API_BASE_URL}/stellar/verified-assets`);
        if (!res.ok) throw new Error("HTTP " + res.status);
        const json = await res.json();
        if (!cancelled) {
          setVerifiedAssets(json.assets ?? []);
          // Default to USDC if available, else first asset
          if (json.assets?.length > 0) {
            const hasUSDC = json.assets.find((a: any) => a.code === "USDC");
            setRecipientAssetCode(hasUSDC ? "USDC" : json.assets[0].code);
          }
        }
      } catch (e) {
        console.warn("Could not load verified assets", e);
      } finally {
        if (!cancelled) setAssetsLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const isValidDestination = useMemo(() => {
    if (!form.destination) return false;
    return StrKey.isValidEd25519PublicKey(form.destination);
  }, [form.destination]);

  const isValidAmount = useMemo(() => {
    const num = Number(form.amount);
    return form.amount !== "" && !Number.isNaN(num) && num > 0;
  }, [form.amount]);

  const rawLinkDataString = useMemo(() => {
    return JSON.stringify({
      amount: form.amount,
      asset: recipientAssetCode,
      destination: form.destination,
      memo: form.memo,
    });
  }, [form.amount, recipientAssetCode, form.destination, form.memo]);

  const handleGenerate = async () => {
    if (!isValidAmount || !isValidDestination) {
      Alert.alert("Invalid Input", "Please check your amount and destination.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/links/metadata`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          amount: Number(form.amount),
          asset: recipientAssetCode,
          destination: form.destination,
          memo: form.memo || undefined,
        }),
      });

      const json = await res.json();
      if (!res.ok) {
        throw new Error(json?.message || "Generation failed.");
      }

      const result = json as LinkMetadataSuccess;
      if (result.success) {
        setCanonicalData(result.data.canonical);
      }
    } catch (e: any) {
      Alert.alert("Error", e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleShare = async () => {
    const url = canonicalData || `https://quickex.to/${form.destination}/${form.amount}?asset=${recipientAssetCode}${form.memo ? `&memo=${encodeURIComponent(form.memo)}` : ""}`;
    try {
      await Share.share({
        message: `Pay me via QuickEx:\n${url}`,
      });
    } catch (error: any) {
      Alert.alert("Error sharing", error.message);
    }
  };

  const handleCopy = async () => {
    const url = canonicalData || `https://quickex.to/${form.destination}/${form.amount}?asset=${recipientAssetCode}${form.memo ? `&memo=${encodeURIComponent(form.memo)}` : ""}`;
    await Clipboard.setStringAsync(url);
    Alert.alert("Copied", "Payment link copied to clipboard");
  };

  return (
    <SafeAreaView style={[styles.container, isDark && styles.darkContainer]}>
      <ScrollView contentContainerStyle={styles.scrollContent} keyboardShouldPersistTaps="handled">
        <Text style={[styles.title, isDark && styles.darkText]}>Create Link</Text>
        <Text style={[styles.subtitle, isDark && styles.darkText]}>
          Generate a payment request link instantly.
        </Text>

        {/* Amount Input */}
        <View style={styles.inputGroup}>
          <Text style={[styles.label, isDark && styles.darkText]}>Amount</Text>
          <View style={[styles.rowInput, isDark && styles.darkInputGroup]}>
            <TextInput
              style={[styles.inputLarge, isDark && styles.darkText]}
              placeholder="0.00"
              placeholderTextColor={isDark ? "#888" : "#ccc"}
              keyboardType="numeric"
              value={form.amount}
              onChangeText={(val) => setForm({ ...form, amount: val })}
            />
            {assetsLoading ? (
              <ActivityIndicator size="small" color="#000" style={{ padding: 10 }} />
            ) : (
              <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.assetScroll}>
                {verifiedAssets.map((a) => (
                  <TouchableOpacity
                    key={a.code}
                    style={[
                      styles.assetPill,
                      recipientAssetCode === a.code && styles.assetPillActive,
                      isDark && recipientAssetCode === a.code && styles.darkAssetPillActive,
                    ]}
                    onPress={() => setRecipientAssetCode(a.code)}
                  >
                    <Text
                      style={[
                        styles.assetPillText,
                        recipientAssetCode === a.code && styles.assetPillTextActive,
                      ]}
                    >
                      {a.code}
                    </Text>
                  </TouchableOpacity>
                ))}
              </ScrollView>
            )}
          </View>
        </View>

        {/* Destination Address */}
        <View style={styles.inputGroup}>
          <Text style={[styles.label, isDark && styles.darkText]}>Destination</Text>
          <TextInput
            style={[styles.input, isDark && styles.darkInput, isDark && styles.darkText]}
            placeholder="G..."
            placeholderTextColor={isDark ? "#888" : "#ccc"}
            value={form.destination}
            onChangeText={(val) => setForm({ ...form, destination: val })}
            autoCapitalize="none"
            autoCorrect={false}
          />
          {form.destination !== "" && !isValidDestination && (
            <Text style={styles.errorText}>Invalid Stellar Public Key</Text>
          )}
        </View>

        {/* Memo */}
        <View style={styles.inputGroup}>
          <Text style={[styles.label, isDark && styles.darkText]}>Memo (Optional)</Text>
          <TextInput
            style={[styles.input, isDark && styles.darkInput, isDark && styles.darkText]}
            placeholder="What's this for?"
            placeholderTextColor={isDark ? "#888" : "#ccc"}
            value={form.memo}
            onChangeText={(val) => setForm({ ...form, memo: val })}
          />
        </View>

        <TouchableOpacity
          style={[styles.generateButton, (!isValidAmount || !isValidDestination) && styles.disabledButton]}
          onPress={handleGenerate}
          disabled={loading || !isValidAmount || !isValidDestination}
        >
          {loading ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.generateButtonText}>Generate Link</Text>
          )}
        </TouchableOpacity>

        {canonicalData && (
          <View style={[styles.resultCard, isDark && styles.darkResultCard]}>
            <Text style={[styles.resultTitle, isDark && styles.darkText]}>Link Ready!</Text>
            
            <View style={styles.actionRow}>
              <TouchableOpacity style={styles.actionButton} onPress={handleShare}>
                <Text style={styles.actionButtonText}>Share Link</Text>
              </TouchableOpacity>
              
              <TouchableOpacity style={styles.actionButtonSecondary} onPress={handleCopy}>
                <Text style={styles.actionButtonTextSecondary}>Copy Link</Text>
              </TouchableOpacity>
            </View>

            <TouchableOpacity
              style={styles.previewButton}
              onPress={() => setQrModalVisible(true)}
            >
              <Text style={styles.previewButtonText}>Preview QR Code</Text>
            </TouchableOpacity>
          </View>
        )}
      </ScrollView>

      {/* QR Preview Modal Full Screen */}
      <QRPreviewModal
        visible={qrModalVisible}
        value={rawLinkDataString}
        onClose={() => setQrModalVisible(false)}
      />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#ffffff",
  },
  darkContainer: {
    backgroundColor: "#000000",
  },
  scrollContent: {
    padding: 24,
  },
  title: {
    fontSize: 32,
    fontWeight: "bold",
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 16,
    color: "#666",
    marginBottom: 32,
  },
  inputGroup: {
    marginBottom: 24,
  },
  label: {
    fontSize: 14,
    fontWeight: "600",
    marginBottom: 8,
    color: "#333",
    textTransform: "uppercase",
  },
  rowInput: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#f5f5f5",
    borderRadius: 16,
    paddingRight: 8,
  },
  darkInputGroup: {
    backgroundColor: "#1c1c1e",
  },
  inputLarge: {
    flex: 1,
    fontSize: 32,
    fontWeight: "bold",
    paddingVertical: 16,
    paddingHorizontal: 16,
  },
  assetScroll: {
    flexDirection: "row",
    maxWidth: "50%",
  },
  assetPill: {
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 12,
    marginRight: 8,
    backgroundColor: "#e5e5ea",
    justifyContent: "center",
  },
  assetPillActive: {
    backgroundColor: "#000",
  },
  darkAssetPillActive: {
    backgroundColor: "#fff",
  },
  assetPillText: {
    fontSize: 14,
    fontWeight: "600",
    color: "#000",
  },
  assetPillTextActive: {
    color: "#fff",
  },
  input: {
    backgroundColor: "#f5f5f5",
    borderRadius: 16,
    padding: 16,
    fontSize: 16,
  },
  darkInput: {
    backgroundColor: "#1c1c1e",
  },
  darkText: {
    color: "#fff",
  },
  errorText: {
    color: "#ef4444",
    fontSize: 12,
    marginTop: 8,
  },
  generateButton: {
    backgroundColor: "#2563EB",
    padding: 18,
    borderRadius: 16,
    alignItems: "center",
    marginTop: 16,
    marginBottom: 32,
  },
  disabledButton: {
    backgroundColor: "#93c5fd",
  },
  generateButtonText: {
    color: "#fff",
    fontSize: 18,
    fontWeight: "bold",
  },
  resultCard: {
    backgroundColor: "#fdfdfd",
    borderWidth: 1,
    borderColor: "#e5e5ea",
    borderRadius: 16,
    padding: 20,
    marginTop: 10,
  },
  darkResultCard: {
    backgroundColor: "#1c1c1e",
    borderColor: "#333",
  },
  resultTitle: {
    fontSize: 20,
    fontWeight: "bold",
    marginBottom: 20,
    textAlign: "center",
  },
  actionRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 16,
  },
  actionButton: {
    flex: 1,
    backgroundColor: "#10B981",
    padding: 14,
    borderRadius: 12,
    alignItems: "center",
    marginRight: 8,
  },
  actionButtonText: {
    color: "#fff",
    fontWeight: "bold",
    fontSize: 16,
  },
  actionButtonSecondary: {
    flex: 1,
    backgroundColor: "#e5e5ea",
    padding: 14,
    borderRadius: 12,
    alignItems: "center",
    marginLeft: 8,
  },
  actionButtonTextSecondary: {
    color: "#000",
    fontWeight: "bold",
    fontSize: 16,
  },
  previewButton: {
    width: "100%",
    padding: 16,
    borderWidth: 2,
    borderColor: "#000",
    borderRadius: 12,
    alignItems: "center",
  },
  previewButtonText: {
    fontWeight: "bold",
    fontSize: 16,
    color: "#000",
  },
});
