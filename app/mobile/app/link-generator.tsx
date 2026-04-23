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
  Alert,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import Constants from "expo-constants";
import * as Clipboard from "expo-clipboard";
import { StrKey } from "@stellar/stellar-base";
import { useTranslation } from 'react-i18next';

import { QRPreviewModal } from "../components/QRPreviewModal";
import { useTheme } from "../src/theme/ThemeContext";

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
  const { theme } = useTheme();
  const { t } = useTranslation();

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
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <ScrollView contentContainerStyle={styles.scrollContent} keyboardShouldPersistTaps="handled">
        <Text style={[styles.title, { color: theme.textPrimary }]}>{t('createPayment')} {t('requestInstantly')}</Text>
        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
          {t('advancedModeDescription')}
        </Text>

        {/* Amount Input */}
        <View style={styles.inputGroup}>
          <Text style={[styles.label, { color: theme.textPrimary }]}>{t('amountLabel')}</Text>
          <View style={[styles.rowInput, { backgroundColor: theme.inputBg }]}>
            <TextInput
              style={[styles.inputLarge, { color: theme.inputText }]}
              placeholder={t('amountPlaceholder')}
              placeholderTextColor={theme.inputPlaceholder}
              keyboardType="numeric"
              value={form.amount}
              onChangeText={(val) => setForm({ ...form, amount: val })}
            />
            {assetsLoading ? (
              <ActivityIndicator size="small" color={theme.primary} style={{ padding: 10 }} />
            ) : (
              <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.assetScroll}>
                {verifiedAssets.map((a) => (
                  <TouchableOpacity
                    key={a.code}
                    style={[
                      styles.assetPill,
                      { backgroundColor: theme.chipBg },
                      recipientAssetCode === a.code && { backgroundColor: theme.chipActiveBg },
                    ]}
                    onPress={() => setRecipientAssetCode(a.code)}
                  >
                    <Text
                      style={[
                        styles.assetPillText,
                        { color: theme.chipText },
                        recipientAssetCode === a.code && { color: theme.chipActiveText },
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
          <Text style={[styles.label, { color: theme.textPrimary }]}>{t('destinationLabel')}</Text>
          <TextInput
            style={[styles.input, { backgroundColor: theme.inputBg, color: theme.inputText }]}
            placeholder={t('destinationPlaceholder')}
            placeholderTextColor={theme.inputPlaceholder}
            value={form.destination}
            onChangeText={(val) => setForm({ ...form, destination: val })}
            autoCapitalize="none"
            autoCorrect={false}
          />
          {form.destination !== "" && !isValidDestination && (
            <Text style={[styles.errorText, { color: theme.status.error }]}>{t('invalidPublicKey')}</Text>
          )}
        </View>

        {/* Memo */}
        <View style={styles.inputGroup}>
          <Text style={[styles.label, { color: theme.textPrimary }]}>{t('memoLabel')}</Text>
          <TextInput
            style={[styles.input, { backgroundColor: theme.inputBg, color: theme.inputText }]}
            placeholder={t('memoPlaceholder')}
            placeholderTextColor={theme.inputPlaceholder}
            value={form.memo}
            onChangeText={(val) => setForm({ ...form, memo: val })}
          />
        </View>

        <TouchableOpacity
          style={[
            styles.generateButton,
            { backgroundColor: theme.status.info },
            (!isValidAmount || !isValidDestination) && { opacity: 0.5 },
          ]}
          onPress={handleGenerate}
          disabled={loading || !isValidAmount || !isValidDestination}
        >
          {loading ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={[styles.generateButtonText, { color: theme.buttonPrimaryText }]}>{t('linkGenerator')}</Text>
          )}
        </TouchableOpacity>

        {canonicalData && (
          <View style={[styles.resultCard, { backgroundColor: theme.surface, borderColor: theme.border }]}>
            <Text style={[styles.resultTitle, { color: theme.textPrimary }]}>{t('linkReady')}</Text>
            
            <View style={styles.actionRow}>
              <TouchableOpacity style={[styles.actionButton, { backgroundColor: theme.status.success }]} onPress={handleShare}>
                <Text style={[styles.actionButtonText, { color: theme.buttonPrimaryText }]}>{t('shareLink')}</Text>
              </TouchableOpacity>
              
              <TouchableOpacity style={[styles.actionButtonSecondary, { backgroundColor: theme.chipBg }]} onPress={handleCopy}>
                <Text style={[styles.actionButtonTextSecondary, { color: theme.textPrimary }]}>{t('copyLink')}</Text>
              </TouchableOpacity>
            </View>

            <TouchableOpacity
              style={[styles.previewButton, { borderColor: theme.buttonSecondaryBorder }]}
              onPress={() => setQrModalVisible(true)}
            >
              <Text style={[styles.previewButtonText, { color: theme.buttonSecondaryText }]}>{t('previewQR')}</Text>
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
    marginBottom: 32,
  },
  inputGroup: {
    marginBottom: 24,
  },
  label: {
    fontSize: 14,
    fontWeight: "600",
    marginBottom: 8,
    textTransform: "uppercase",
  },
  rowInput: {
    flexDirection: "row",
    alignItems: "center",
    borderRadius: 16,
    paddingRight: 8,
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
    justifyContent: "center",
  },
  assetPillText: {
    fontSize: 14,
    fontWeight: "600",
  },
  input: {
    borderRadius: 16,
    padding: 16,
    fontSize: 16,
  },
  errorText: {
    fontSize: 12,
    marginTop: 8,
  },
  generateButton: {
    padding: 18,
    borderRadius: 16,
    alignItems: "center",
    marginTop: 16,
    marginBottom: 32,
  },
  generateButtonText: {
    fontSize: 18,
    fontWeight: "bold",
  },
  resultCard: {
    borderWidth: 1,
    borderRadius: 16,
    padding: 20,
    marginTop: 10,
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
    padding: 14,
    borderRadius: 12,
    alignItems: "center",
    marginRight: 8,
  },
  actionButtonText: {
    fontWeight: "bold",
    fontSize: 16,
  },
  actionButtonSecondary: {
    flex: 1,
    padding: 14,
    borderRadius: 12,
    alignItems: "center",
    marginLeft: 8,
  },
  actionButtonTextSecondary: {
    fontWeight: "bold",
    fontSize: 16,
  },
  previewButton: {
    width: "100%",
    padding: 16,
    borderWidth: 2,
    borderRadius: 12,
    alignItems: "center",
  },
  previewButtonText: {
    fontWeight: "bold",
    fontSize: 16,
  },
});
