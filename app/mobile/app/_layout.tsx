import {
  ThemeProvider,
  type Theme as NavigationTheme,
} from "@react-navigation/native";
import * as Linking from "expo-linking";
import { Stack, useRouter } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { useEffect, useMemo } from "react";
import { useColorScheme } from "react-native";
// Ensure web build or Expo web uses the local backend during development
if (typeof document !== "undefined" && !(global as any).API_BASE_URL) {
  // Expo web typically runs on localhost; ensure the app hits the backend on port 4000
  (global as any).API_BASE_URL = "http://localhost:4000";
}
import { OfflineBanner } from "../components/resilience/offline-banner";
import { AppLockOverlay } from "../components/security/app-lock-overlay";
import { SecurityProvider, useSecurity } from "../hooks/use-security";
import { NotificationProvider } from "../components/notifications/NotificationContext";
import ToastNotification from "../components/notifications/ToastNotification";
import NotificationCenter from "../components/notifications/NotificationCenter";
import { usePaymentListener } from "../hooks/usePaymentListener";
import { useOnboarding } from "../hooks/useOnboarding";

import { parsePaymentLink } from "@/utils/parse-payment-link";

// ── Theme System v2 ──────────────────────────────────────────────────────────
import { QuickExThemeProvider, useTheme } from "../src/theme/ThemeContext";

function useDeepLinkHandler() {
  const router = useRouter();

  useEffect(() => {
    function handleURL(event: { url: string }) {
      const result = parsePaymentLink(event.url);
      if (!result.valid) return;

      const { username, amount, asset, memo, privacy } = result.data;
      router.replace({
        pathname: "/payment-confirmation",
        params: {
          username,
          amount,
          asset,
          ...(memo ? { memo } : {}),
          privacy: String(privacy),
        },
      });
    }

    const subscription = Linking.addEventListener("url", handleURL);

    // Handle cold-start deep link
    Linking.getInitialURL().then((url) => {
      if (url) handleURL({ url });
    });

    return () => subscription.remove();
  }, [router]);
}

function DevPoller() {
  // demo public key used by send_test_payment.js
  const demo = "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP";
  // call the hook so polling starts. Hook internally is a no-op in prod.
  usePaymentListener(demo);
  return null;
}

export default function RootLayout() {
  return (
    <QuickExThemeProvider>
      <ThemeBridge />
    </QuickExThemeProvider>
  );
}

/**
 * Bridges our token-based theme into React Navigation's ThemeProvider
 * so that Stack/Tab navigators inherit the correct colours.
 */
function ThemeBridge() {
  const { theme, isDark } = useTheme();

  const navTheme: NavigationTheme = useMemo(
    () => ({
      dark: isDark,
      colors: {
        primary: theme.primary,
        background: theme.background,
        card: theme.headerBg,
        text: theme.textPrimary,
        border: theme.border,
        notification: theme.status.error,
      },
      fonts: {
        regular: { fontFamily: 'System', fontWeight: '400' as const },
        medium: { fontFamily: 'System', fontWeight: '500' as const },
        bold: { fontFamily: 'System', fontWeight: '700' as const },
        heavy: { fontFamily: 'System', fontWeight: '800' as const },
      },
    }),
    [theme, isDark],
  );

  return (
    <ThemeProvider value={navTheme}>
      <SecurityProvider>
        <NotificationProvider>
          {/* Dev-only global poller: ensures polling runs on web during development
              even if the wallet screen isn't active. */}
          {process.env.NODE_ENV !== "production" ? (
            // start polling for demo address used by send_test_payment.js
            // eslint-disable-next-line react/jsx-no-useless-fragment
            <DevPoller />
          ) : null}
          <AppShell />
          <ToastNotification />
        </NotificationProvider>
      </SecurityProvider>
      <StatusBar style={isDark ? "light" : "dark"} />
    </ThemeProvider>
  );
}

function AppShell() {
  const { isAppLocked, isReady, settings, unlockApp } = useSecurity();
  const { hasCompletedOnboarding, isLoading: onboardingLoading } = useOnboarding();
  useDeepLinkHandler();

  if (onboardingLoading) {
    return null; // Show loading screen while checking onboarding status
  }

  return (
    <>
      <OfflineBanner />
      <Stack screenOptions={{ headerShown: false }}>
        <Stack.Screen name="onboarding" />
        <Stack.Screen name="index" />
        <Stack.Screen name="security" />
        <Stack.Screen name="wallet-connect" />
        <Stack.Screen name="scan-to-pay" />
        <Stack.Screen name="payment-confirmation" />
        <Stack.Screen name="transactions" />
        <Stack.Screen name="contacts" />
        <Stack.Screen name="add-contact" />
        <Stack.Screen name="edit-contact" />
      </Stack>
      {isReady && settings.biometricLockEnabled ? (
        <AppLockOverlay visible={isAppLocked} onUnlock={unlockApp} />
      ) : null}
    </>
  );
}
