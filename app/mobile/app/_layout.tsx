import { DarkTheme, DefaultTheme, ThemeProvider } from '@react-navigation/native';
import * as Linking from 'expo-linking';
import { Stack, useRouter } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { useEffect } from 'react';
import { useColorScheme } from 'react-native';
import { OfflineBanner } from '../components/resilience/offline-banner';

import { parsePaymentLink } from '@/utils/parse-payment-link';

function useDeepLinkHandler() {
  const router = useRouter();

  useEffect(() => {
    function handleURL(event: { url: string }) {
      const result = parsePaymentLink(event.url);
      if (!result.valid) return;

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
    }

    const subscription = Linking.addEventListener('url', handleURL);

    // Handle cold-start deep link
    Linking.getInitialURL().then((url) => {
      if (url) handleURL({ url });
    });

    return () => subscription.remove();
  }, [router]);
}

export default function RootLayout() {
  const colorScheme = useColorScheme();
  useDeepLinkHandler();

  return (
    <ThemeProvider value={colorScheme === 'dark' ? DarkTheme : DefaultTheme}>
      <OfflineBanner />
      <Stack screenOptions={{ headerShown: false }}>
        <Stack.Screen name="index" />
        <Stack.Screen name="wallet-connect" />
        <Stack.Screen name="scan-to-pay" />
        <Stack.Screen name="payment-confirmation" />
        <Stack.Screen name="transactions" />
      </Stack>
      <StatusBar style="auto" />
    </ThemeProvider>
  );
}
