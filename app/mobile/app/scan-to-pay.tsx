import { CameraView, useCameraPermissions } from 'expo-camera';
import { useRouter } from 'expo-router';
import React, { useCallback, useRef, useState } from 'react';
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { parsePaymentLink } from '@/utils/parse-payment-link';
import { useTheme } from '../src/theme/ThemeContext';

import * as Haptics from 'expo-haptics';
import { Ionicons } from '@expo/vector-icons';

export default function ScanToPayScreen() {
  const router = useRouter();
  const { theme } = useTheme();
  const [permission, requestPermission] = useCameraPermissions();
  const [error, setError] = useState<string | null>(null);
  const processingRef = useRef(false);

  const [flashEnabled, setFlashEnabled] = useState(false);
  const [scanned, setScanned] = useState(false);

  const handleBarCodeScanned = useCallback(
  async ({ data }: { data: string }) => {
    if (processingRef.current || scanned) return;

    processingRef.current = true;
    setScanned(true);

    const start = Date.now();

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

      // performance check
      const duration = Date.now() - start;
      console.log('Scan → confirm (ms):', duration);
    } else {
      await Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);

      setError(result.error || 'Invalid QR code');

      setTimeout(() => {
        processingRef.current = false;
        setScanned(false);
      }, 1500);
    }
  },
  [router, scanned],
);

  const dismissError = useCallback(() => {
    setError(null);
    processingRef.current = false;
  }, []);

  if (!permission) {
    return (
      <SafeAreaView style={[styles.centered, { backgroundColor: theme.background }]}>
        <ActivityIndicator
          size="large"
          color={theme.primary}
          accessibilityLabel="Loading camera permission status"
        />
      </SafeAreaView>
    );
  }

  if (!permission.granted) {
    return (
      <SafeAreaView style={[styles.centered, { backgroundColor: theme.background }]}>
        <Text
          style={[styles.permTitle, { color: theme.textPrimary }]}
          accessibilityRole="header"
        >
          Camera Permission Required
        </Text>
        <Text style={[styles.permBody, { color: theme.textSecondary }]}>
          QuickEx needs camera access to scan QR payment codes.
        </Text>
        <Pressable
          style={[styles.primaryBtn, { backgroundColor: theme.buttonPrimaryBg }]}
          onPress={requestPermission}
          accessibilityLabel="Grant camera permission access"
          accessibilityRole="button"
          accessibilityHint="Double-tap to allow QuickEx to use the camera for scanning QR codes"
        >
          <Text style={[styles.primaryBtnText, { color: theme.buttonPrimaryText }]}>Grant Access</Text>
        </Pressable>
        <Pressable
          style={styles.secondaryBtn}
          onPress={() => router.back()}
          accessibilityLabel="Go back to previous screen"
          accessibilityRole="button"
          accessibilityHint="Return to the previous screen without granting camera permission"
        >
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
        <Text
          style={styles.title}
          accessibilityRole="header"
        >
          Scan to Pay
        </Text>
        <Text style={styles.hint}>
          Point your camera at a QuickEx QR code
        </Text>

        {/* Viewfinder */}
        <View
          style={styles.viewfinder}
          accessibilityElementsHidden={true}
          importantForAccessibility="no-hide-descendants"
        >
          <View
            style={[styles.corner, styles.topLeft]}
            accessibilityElementsHidden={true}
            importantForAccessibility="no"
          />
          <View
            style={[styles.corner, styles.topRight]}
            accessibilityElementsHidden={true}
            importantForAccessibility="no"
          />
          <View
            style={[styles.corner, styles.bottomLeft]}
            accessibilityElementsHidden={true}
            importantForAccessibility="no"
          />
          <View
            style={[styles.corner, styles.bottomRight]}
            accessibilityElementsHidden={true}
            importantForAccessibility="no"
          />
        </View>

        <View style={styles.controls}>
  <Pressable
    onPress={() => setFlashEnabled((prev) => !prev)}
    style={styles.controlButton}
    accessibilityLabel={`${flashEnabled ? 'Turn camera flash off' : 'Turn camera flash on'}. Flash is currently ${flashEnabled ? 'on' : 'off'}`}
    accessibilityRole="button"
    accessibilityState={{ checked: flashEnabled }}
    accessibilityHint="Double-tap to toggle the camera flash on or off"
    hitSlop={{ top: 8, left: 8, right: 8, bottom: 8 }}
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
          <Pressable
            style={styles.errorBanner}
            onPress={dismissError}
            accessibilityLabel={`Error: ${error}. Tap to dismiss this error message`}
            accessibilityRole="alert"
            accessibilityLiveRegion="assertive"
          >
            <Text style={styles.errorBannerText}>{error}</Text>
            <Text style={styles.errorDismiss}>Tap to dismiss</Text>
          </Pressable>
        )}

        <View style={styles.footer}>
          <Pressable
            style={styles.closeBtn}
            onPress={() => router.back()}
            accessibilityLabel="Close QR scanner and return to previous screen"
            accessibilityRole="button"
            accessibilityHint="Double-tap to exit the scan to pay screen"
          >
            <Text style={styles.closeBtnText}>Close</Text>
          </Pressable>
        </View>
      </SafeAreaView>
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
  // Camera overlay text — intentionally white for camera contrast
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
    minHeight: 48,
    paddingVertical: 14,
    paddingHorizontal: 24,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
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
    minHeight: 48,
    minWidth: 160,
    paddingVertical: 14,
    paddingHorizontal: 48,
    borderRadius: 30,
    alignItems: 'center',
    justifyContent: 'center',
  },
  closeBtnText: { color: '#fff', fontSize: 17, fontWeight: '600' },
  permTitle: { fontSize: 24, fontWeight: 'bold', marginBottom: 12, textAlign: 'center' },
  permBody: { fontSize: 16, textAlign: 'center', marginBottom: 32, lineHeight: 22 },
  primaryBtn: {
    minHeight: 52,
    paddingVertical: 14,
    paddingHorizontal: 36,
    borderRadius: 10,
    marginBottom: 12,
    width: '100%',
    alignItems: 'center',
    justifyContent: 'center',
  },
  controls: {
    position: 'absolute',
    bottom: 40,
    alignSelf: 'center',
    flexDirection: 'row',
  },
  controlButton: {
    backgroundColor: 'rgba(0,0,0,0.6)',
    minHeight: 48,
    minWidth: 48,
    padding: 12,
    borderRadius: 50,
    alignItems: 'center',
    justifyContent: 'center',
  },
  primaryBtnText: { fontSize: 17, fontWeight: '600' },
  secondaryBtn: {
    minHeight: 48,
    padding: 14,
    alignItems: 'center',
    justifyContent: 'center',
  },
  secondaryBtnText: { fontSize: 16 },
});
