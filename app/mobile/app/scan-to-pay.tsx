import { CameraView, useCameraPermissions } from 'expo-camera';
import { useRouter } from 'expo-router';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Pressable,
  StyleSheet,
  Text,
  View,
  Modal,
  ScrollView,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { parsePaymentLink } from '@/utils/parse-payment-link';
import { useTheme } from '../src/theme/ThemeContext';
import { CrashReportingService } from '@/services/CrashReportingService';

import * as Haptics from 'expo-haptics';
import { Ionicons } from '@expo/vector-icons';

interface ScannedPaymentData {
  username: string;
  amount: string;
  asset: string;
  memo?: string;
  privacy: boolean;
}

export default function ScanToPayScreen() {
  const router = useRouter();
  const { theme } = useTheme();
  const [permission, requestPermission] = useCameraPermissions();
  const [error, setError] = useState<string | null>(null);
  const processingRef = useRef(false);

  const [flashEnabled, setFlashEnabled] = useState(false);
  const [scanned, setScanned] = useState(false);
  const resetTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (resetTimerRef.current) clearTimeout(resetTimerRef.current);
    };
  }, []);

  const handleBarCodeScanned = useCallback(
    async ({ data }: { data: string }) => {
      if (processingRef.current || scanned) return;

      processingRef.current = true;
      setScanned(true);

      const result = parsePaymentLink(data);

      if (result.valid) {
        await Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);

        const { username, amount, asset, memo, privacy } = result.data;
        router.replace({
          pathname: '/payment-confirmation',
          params: {
            username,
            amount,
            asset,
            ...(memo ? { memo } : {}),
            privacy: String(privacy),
          },
        });
        return;
      }

      await Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      setError(result.error || 'Invalid QR code');
      resetTimerRef.current = setTimeout(() => {
        processingRef.current = false;
        setScanned(false);
        resetTimerRef.current = null;
      }, 1500);
    },
    [router, scanned],
  );

  const dismissError = useCallback(() => {
    setError(null);
    processingRef.current = false;
    if (resetTimerRef.current) {
      clearTimeout(resetTimerRef.current);
      resetTimerRef.current = null;
    }
    setScanned(false);
  }, []);

  const handleConfirmPayment = async () => {
    if (!paymentData) return;

    setIsProcessing(true);
    try {
      CrashReportingService.recordUserAction('Payment confirmed', {
        username: paymentData.username,
        asset: paymentData.asset,
        amount: paymentData.amount,
      });

      await Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);

      router.replace({
        pathname: '/payment-confirmation',
        params: {
          username: paymentData.username,
          amount: paymentData.amount,
          asset: paymentData.asset,
          ...(paymentData.memo ? { memo: paymentData.memo } : {}),
          privacy: String(paymentData.privacy),
        },
      });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to process payment';
      CrashReportingService.recordError(errorMsg);
      Alert.alert('Error', errorMsg);
      setIsProcessing(false);
      setShowConfirmation(false);
    }
  };

  const handleRejectPayment = () => {
    if (!paymentData) return;

    CrashReportingService.recordUserAction('Payment rejected', {
      username: paymentData.username,
      asset: paymentData.asset,
    });

    setShowConfirmation(false);
    setPaymentData(null);
    processingRef.current = false;
    setScanned(false);
  };

  if (!permission) {
    return (
      <SafeAreaView style={[styles.centered, { backgroundColor: theme.background }]}>
        <ActivityIndicator size="large" color={theme.primary} />
      </SafeAreaView>
    );
  }

  if (!permission.granted) {
    return (
      <SafeAreaView style={[styles.centered, { backgroundColor: theme.background }]}>
        <Text style={[styles.permTitle, { color: theme.textPrimary }]}>Camera Permission Required</Text>
        <Text style={[styles.permBody, { color: theme.textSecondary }]}>
          QuickEx needs camera access to scan QR payment codes.
        </Text>
        <Pressable style={[styles.primaryBtn, { backgroundColor: theme.buttonPrimaryBg }]} onPress={requestPermission}>
          <Text style={[styles.primaryBtnText, { color: theme.buttonPrimaryText }]}>Grant Access</Text>
        </Pressable>
        <Pressable style={styles.secondaryBtn} onPress={() => router.back()}>
          <Text style={[styles.secondaryBtnText, { color: theme.textSecondary }]}>Go Back</Text>
        </Pressable>
      </SafeAreaView>
    );
  }

  return (
    <View style={styles.container}>
      <CameraView
        style={StyleSheet.absoluteFillObject}
        facing="back"
        enableTorch={flashEnabled}
        onBarcodeScanned={handleBarCodeScanned}
        barcodeScannerSettings={{
          barcodeTypes: ['qr'],
        }}
      />

      {/* Overlay — intentionally uses white-on-transparent for camera readability */}
      <SafeAreaView style={styles.overlay} pointerEvents="box-none">
        <Text style={styles.title}>Scan to Pay</Text>
        <Text style={styles.hint}>Point your camera at a QuickEx QR code</Text>

        {/* Viewfinder */}
        <View style={styles.viewfinder}>
          <View style={[styles.corner, styles.topLeft]} />
          <View style={[styles.corner, styles.topRight]} />
          <View style={[styles.corner, styles.bottomLeft]} />
          <View style={[styles.corner, styles.bottomRight]} />
        </View>

        <View style={styles.controls}>
          <Pressable
            onPress={() => setFlashEnabled((prev) => !prev)}
            style={styles.controlButton}
            accessibilityRole="button"
            accessibilityLabel={flashEnabled ? 'Turn flash off' : 'Turn flash on'}
          >
            <Ionicons
              name={flashEnabled ? 'flash' : 'flash-off'}
              size={24}
              color="white"
            />
          </Pressable>
        </View>

        {/* Error banner */}
        {error && (
          <Pressable style={styles.errorBanner} onPress={dismissError}>
            <Text style={styles.errorBannerText}>{error}</Text>
            <Text style={styles.errorDismiss}>Tap to dismiss</Text>
          </Pressable>
        )}

        <View style={styles.footer}>
          <Pressable style={styles.closeBtn} onPress={() => router.back()}>
            <Text style={styles.closeBtnText}>Close</Text>
          </Pressable>
        </View>
      </SafeAreaView>

      {/* Payment Confirmation Modal */}
      <Modal visible={showConfirmation} transparent animationType="slide" onRequestClose={handleRejectPayment}>
        <SafeAreaView style={[styles.modalContainer, { backgroundColor: theme.background }]}>
          <View style={styles.modalHeader}>
            <Pressable onPress={handleRejectPayment} hitSlop={8}>
              <Ionicons name="close" size={24} color={theme.textPrimary} />
            </Pressable>
            <Text style={[styles.modalTitle, { color: theme.textPrimary }]}>Confirm Payment</Text>
            <View style={{ width: 24 }} />
          </View>

          <ScrollView style={styles.modalContent} showsVerticalScrollIndicator={false}>
            <View style={[styles.amountCard, { borderColor: theme.borderColor }]}>
              <Text style={[styles.amountLabel, { color: theme.textSecondary }]}>You're sending</Text>
              <Text style={[styles.amount, { color: theme.textPrimary }]}>
                {paymentData?.amount} {paymentData?.asset}
              </Text>
            </View>

            <View style={[styles.detailsSection, { borderColor: theme.borderColor }]}>
              <View style={styles.detailRow}>
                <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>Recipient</Text>
                <Text style={[styles.detailValue, { color: theme.textPrimary }]}>{paymentData?.username}</Text>
              </View>

              <View style={[styles.detailDivider, { backgroundColor: theme.borderColor }]} />

              <View style={styles.detailRow}>
                <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>Asset</Text>
                <Text style={[styles.detailValue, { color: theme.textPrimary }]}>{paymentData?.asset}</Text>
              </View>

              {paymentData?.memo && (
                <>
                  <View style={[styles.detailDivider, { backgroundColor: theme.borderColor }]} />
                  <View style={styles.detailRow}>
                    <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>Memo</Text>
                    <Text style={[styles.detailValue, { color: theme.textPrimary }]}>{paymentData.memo}</Text>
                  </View>
                </>
              )}

              <View style={[styles.detailDivider, { backgroundColor: theme.borderColor }]} />

              <View style={styles.detailRow}>
                <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>Privacy</Text>
                <Text style={[styles.detailValue, { color: theme.textPrimary }]}>
                  {paymentData?.privacy ? 'Enabled' : 'Disabled'}
                </Text>
              </View>
            </View>

            <View style={styles.warningBox}>
              <Ionicons name="alert-circle" size={16} color="#f59e0b" />
              <Text style={[styles.warningText, { color: theme.textSecondary }]}>
                Please review the details carefully before confirming.
              </Text>
            </View>
          </ScrollView>

          <View style={styles.modalActions}>
            <Pressable
              style={[styles.confirmButton, { backgroundColor: theme.buttonPrimaryBg }]}
              onPress={handleConfirmPayment}
              disabled={isProcessing}
              android_ripple={{ color: 'rgba(0,0,0,0.2)' }}
            >
              {isProcessing ? (
                <ActivityIndicator color={theme.buttonPrimaryText} />
              ) : (
                <>
                  <Ionicons name="checkmark-circle" size={18} color={theme.buttonPrimaryText} />
                  <Text style={[styles.buttonText, { color: theme.buttonPrimaryText }]}>Confirm & Sign</Text>
                </>
              )}
            </Pressable>

            <Pressable
              style={[styles.cancelButton, { borderColor: theme.borderColor }]}
              onPress={handleRejectPayment}
              disabled={isProcessing}
              android_ripple={{ color: 'rgba(0,0,0,0.1)' }}
            >
              <Text style={[styles.buttonText, { color: theme.textSecondary }]}>Cancel</Text>
            </Pressable>
          </View>
        </SafeAreaView>
      </Modal>
    </View>
  );
}

const CORNER = 24;
const BORDER = 3;

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#000' },
  centered: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 32,
  },
  overlay: {
    ...StyleSheet.absoluteFillObject,
    justifyContent: 'flex-start',
    alignItems: 'center',
    paddingTop: 24,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 4,
  },
  hint: {
    fontSize: 15,
    color: 'rgba(255,255,255,0.7)',
    marginBottom: 40,
  },
  viewfinder: {
    width: 250,
    height: 250,
    position: 'relative',
  },
  corner: {
    position: 'absolute',
    width: CORNER,
    height: CORNER,
    borderColor: '#fff',
  },
  topLeft: { top: 0, left: 0, borderTopWidth: BORDER, borderLeftWidth: BORDER },
  topRight: { top: 0, right: 0, borderTopWidth: BORDER, borderRightWidth: BORDER },
  bottomLeft: { bottom: 0, left: 0, borderBottomWidth: BORDER, borderLeftWidth: BORDER },
  bottomRight: { bottom: 0, right: 0, borderBottomWidth: BORDER, borderRightWidth: BORDER },
  errorBanner: {
    marginTop: 32,
    backgroundColor: 'rgba(255,59,48,0.9)',
    paddingVertical: 14,
    paddingHorizontal: 24,
    borderRadius: 12,
    alignItems: 'center',
    maxWidth: 320,
  },
  errorBannerText: { color: '#fff', fontSize: 15, fontWeight: '600', textAlign: 'center' },
  errorDismiss: { color: 'rgba(255,255,255,0.7)', fontSize: 12, marginTop: 4 },
  footer: {
    position: 'absolute',
    bottom: 40,
    alignItems: 'center',
    width: '100%',
  },
  closeBtn: {
    backgroundColor: 'rgba(255,255,255,0.2)',
    paddingVertical: 14,
    paddingHorizontal: 48,
    borderRadius: 30,
  },
  closeBtnText: { color: '#fff', fontSize: 17, fontWeight: '600' },
  permTitle: { fontSize: 24, fontWeight: 'bold', marginBottom: 12, textAlign: 'center' },
  permBody: { fontSize: 16, textAlign: 'center', marginBottom: 32, lineHeight: 22 },
  primaryBtn: {
    paddingVertical: 14,
    paddingHorizontal: 36,
    borderRadius: 10,
    marginBottom: 12,
    width: '100%',
    alignItems: 'center',
  },
  controls: {
    position: 'absolute',
    bottom: 40,
    alignSelf: 'center',
    flexDirection: 'row',
  },
  controlButton: {
    backgroundColor: 'rgba(0,0,0,0.6)',
    padding: 12,
    borderRadius: 50,
  },
  primaryBtnText: { fontSize: 17, fontWeight: '600' },
  secondaryBtn: { padding: 14 },
  secondaryBtnText: { fontSize: 16 },
  // Modal styles
  modalContainer: {
    flex: 1,
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: 1,
  },
  modalTitle: {
    fontSize: 18,
    fontWeight: '600',
  },
  modalContent: {
    flex: 1,
    padding: 16,
  },
  amountCard: {
    borderWidth: 2,
    borderRadius: 16,
    padding: 20,
    alignItems: 'center',
    marginBottom: 20,
  },
  amountLabel: {
    fontSize: 14,
    marginBottom: 8,
  },
  amount: {
    fontSize: 32,
    fontWeight: '700',
  },
  detailsSection: {
    borderWidth: 1,
    borderRadius: 12,
    padding: 16,
    marginBottom: 20,
  },
  detailRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
  },
  detailLabel: {
    fontSize: 14,
    fontWeight: '500',
  },
  detailValue: {
    fontSize: 14,
    fontWeight: '600',
  },
  detailDivider: {
    height: 1,
  },
  warningBox: {
    flexDirection: 'row',
    gap: 12,
    paddingHorizontal: 12,
    paddingVertical: 10,
    borderRadius: 8,
    backgroundColor: 'rgba(245, 158, 11, 0.1)',
    marginBottom: 20,
    alignItems: 'flex-start',
  },
  warningText: {
    fontSize: 13,
    flex: 1,
    lineHeight: 18,
  },
  modalActions: {
    gap: 12,
    paddingHorizontal: 16,
    paddingBottom: 20,
  },
  confirmButton: {
    flexDirection: 'row',
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
  },
  cancelButton: {
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 10,
    alignItems: 'center',
    borderWidth: 1.5,
  },
  buttonText: {
    fontSize: 16,
    fontWeight: '600',
  },
});
