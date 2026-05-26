/**
 * SAMPLE: App Root Integration
 *
 * This shows where to add the NetworkGuardProvider in your app's root component.
 * Place this in your main app file (app/index.tsx, app.tsx, _app.tsx, etc.)
 */

import React from "react";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import { SafeAreaProvider } from "react-native-safe-area-context";

// ── Providers ────────────────────────────────────────────────────────────────

import { WalletProvider } from "./hooks/useWalletContext";
import { NetworkGuardProvider } from "./contexts/NetworkGuardContext";
import { ThemeProvider } from "./src/theme/ThemeContext";
import { NotificationProvider } from "./components/notifications/NotificationContext";

// ── Components ───────────────────────────────────────────────────────────────

import { GlobalNetworkBanner } from "./components/wallet/GlobalNetworkBanner";
import { WalletSyncBridge } from "./components/wallet/WalletSyncBridge";
import { RootNavigator } from "./app/RootNavigator";

/**
 * Root App Component
 *
 * Provider hierarchy (order matters):
 * 1. GestureHandlerRootView - Must wrap everything for react-native-gesture-handler
 * 2. SafeAreaProvider - Provides safe area insets for notches/home indicators
 * 3. ThemeProvider - Provides theme/styling context
 * 4. WalletProvider - Manages wallet connection state
 * 5. NetworkGuardProvider - MUST come after WalletProvider
 * 6. NotificationProvider - Depends on wallet context
 * 7. GlobalNetworkBanner - Shows network status banner
 * 8. RootNavigator - Your app's navigation/screens
 */
export default function RootApp() {
  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
      <SafeAreaProvider>
        <ThemeProvider>
          <WalletProvider>
            {/* ← NetworkGuardProvider MUST come AFTER WalletProvider */}
            <NetworkGuardProvider expectedNetwork="testnet">
              <NotificationProvider>
                {/* Global components that should appear above all screens */}
                <GlobalNetworkBanner />

                {/* Watches wallet changes and syncs notifications */}
                <WalletSyncBridge />

                {/* Your app's main navigation */}
                <RootNavigator />
              </NotificationProvider>
            </NetworkGuardProvider>
          </WalletProvider>
        </ThemeProvider>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}

/**
 * NEXT STEPS:
 *
 * 1. Wrap transaction actions with NetworkMismatchGuard:
 *    See components/wallet/TransactionActionsWithGuards.tsx for examples
 *
 * 2. Show help modal when user tries blocked actions:
 *    Import WalletSwitchHelpModal and show on guard's onBlocked callback
 *
 * 3. Test the network detection:
 *    - Connect wallet on testnet → banner shows yellow "Stellar Testnet Mode"
 *    - Switch to mainnet → banner turns red with "NETWORK MISMATCH" warning
 *    - Try to pay → actions are blocked with lock icon
 *    - Tap blocked action → help modal shows wallet switching instructions
 *
 * 4. Customize if needed:
 *    - Change expectedNetwork prop to "mainnet" if needed (unlikely for QiuckEx)
 *    - Adjust banner colors in GlobalNetworkBanner.tsx
 *    - Customize guard overlay in NetworkMismatchGuard.tsx
 */
