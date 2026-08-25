import { Link, useRouter } from "expo-router";
import React from "react";
import { EnvironmentSwitcher } from "../components/EnvironmentSwitcher";
import {
  Alert,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Switch,
  Text,
  View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import { LocaleSwitcher } from "../components/LocaleSwitcher";
import { useNotifications } from "../components/notifications/NotificationContext";
import OnboardingResetButton from "../components/onboarding/OnboardingResetButton";
import { ThemeSelector } from "../components/ThemeSelector";
import { useWallet } from "../hooks/useWallet";
import { clearLocalData } from "../services/local-data";
import {
  SYNC_INTERVALS_MINUTES,
  type SyncFrequency,
} from "../services/background-sync";
import { useTheme } from "../src/theme/ThemeContext";
import {
  APP_ENVIRONMENT,
  APP_VERSION,
  BUILD_METADATA,
  BUILD_TAG,
  IS_DEBUG_BUILD,
  STELLAR_NETWORK,
} from "../src/config/build";

const FREQUENCY_OPTIONS: Array<{
  value: SyncFrequency;
  label: string;
  helper: string;
}> = [
  {
    value: "battery-saver",
    label: "Battery Saver",
    helper: `About every ${SYNC_INTERVALS_MINUTES["battery-saver"]} minutes`,
  },
  {
    value: "balanced",
    label: "Balanced",
    helper: `About every ${SYNC_INTERVALS_MINUTES.balanced} minutes`,
  },
  {
    value: "frequent",
    label: "Frequent",
    helper: `About every ${SYNC_INTERVALS_MINUTES.frequent} minutes`,
  },
];

export default function SettingsScreen() {
  const router = useRouter();
  const { theme } = useTheme();
  const { disconnect } = useWallet();
  const {
    backgroundSyncSettings,
    backgroundTaskAvailable,
    isSyncing,
    lastSyncedAt,
    setBackgroundSyncSettings,
    soundEnabled,
    setSoundEnabled,
    syncNow,
  } = useNotifications();

  const handleClearLocalData = () => {
    Alert.alert(
      "Clear Local Data",
      "This action will remove cached app data, sign you out, and clear secure storage. This cannot be undone.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Clear Data",
          style: "destructive",
          onPress: async () => {
            try {
              await disconnect();
              await clearLocalData();
              Alert.alert(
                "Local Data Cleared",
                "All local app data has been removed. Please reconnect your wallet.",
              );
              router.replace("/");
            } catch (error) {
              Alert.alert(
                "Unable to Clear Data",
                "Something went wrong while clearing local data. Please try again.",
              );
            }
          },
        },
      ],
    );
  };

  return (
    <SafeAreaView
      style={[styles.container, { backgroundColor: theme.background }]}
    >
      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.content}
        showsVerticalScrollIndicator={false}
      >
        <Text style={[styles.title, { color: theme.textPrimary }]} accessibilityRole="header">
          Settings
        </Text>

        <ThemeSelector />
        <LocaleSwitcher />

        <View
          style={[
            styles.card,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <Text style={[styles.cardTitle, { color: theme.textPrimary }]} accessibilityRole="header">
            Security
          </Text>

          <Link href="/security-center" asChild>
            <Pressable
              style={styles.row}
              accessibilityLabel="Security Center. Review your security posture and settings."
              accessibilityRole="link"
              accessibilityHint="Double-tap to navigate to the Security Center page"
            >
              <View style={styles.rowCopy} accessibilityElementsHidden={true} importantForAccessibility="no">
                <Text style={[styles.label, { color: theme.textPrimary }]}>
                  Security Center
                </Text>
                <Text style={[styles.helper, { color: theme.textMuted }]}>
                  Review your security posture and settings.
                </Text>
              </View>
              <Text style={[styles.helper, { color: theme.textMuted }]} accessibilityElementsHidden={true} importantForAccessibility="no">→</Text>
            </Pressable>
          </Link>
        </View>

        <View
          style={[
            styles.card,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <Text style={[styles.cardTitle, { color: theme.textPrimary }]} accessibilityRole="header">
            Notifications
          </Text>

          <View
            style={styles.row}
            accessibilityLabel={`Sound Effects. ${soundEnabled ? 'Enabled' : 'Disabled'}. Play a short tone when a new synced notification appears.`}
            accessibilityRole="none"
          >
            <View style={styles.rowCopy} accessibilityElementsHidden={true} importantForAccessibility="no">
              <Text style={[styles.label, { color: theme.textPrimary }]}>
                Sound Effects
              </Text>
              <Text style={[styles.helper, { color: theme.textMuted }]}>
                Play a short tone when a new synced notification appears.
              </Text>
            </View>
            <Switch
              value={soundEnabled}
              onValueChange={setSoundEnabled}
              accessibilityLabel={`Sound Effects toggle, currently ${soundEnabled ? 'on' : 'off'}`}
              accessibilityRole="switch"
              accessibilityState={{ checked: soundEnabled }}
            />
          </View>

          <View
            style={styles.row}
            accessibilityLabel={`App Badge. ${backgroundSyncSettings.badgeEnabled ? 'Enabled' : 'Disabled'}. Keep the launcher badge aligned with unread notifications.`}
            accessibilityRole="none"
          >
            <View style={styles.rowCopy} accessibilityElementsHidden={true} importantForAccessibility="no">
              <Text style={[styles.label, { color: theme.textPrimary }]}>
                App Badge
              </Text>
              <Text style={[styles.helper, { color: theme.textMuted }]}>
                Keep the launcher badge aligned with unread notifications.
              </Text>
            </View>
            <Switch
              value={backgroundSyncSettings.badgeEnabled}
              onValueChange={(value) => {
                void setBackgroundSyncSettings((current) => ({
                  ...current,
                  badgeEnabled: value,
                }));
              }}
              accessibilityLabel={`App Badge toggle, currently ${backgroundSyncSettings.badgeEnabled ? 'on' : 'off'}`}
              accessibilityRole="switch"
              accessibilityState={{ checked: backgroundSyncSettings.badgeEnabled }}
            />
          </View>
        </View>

        <View
          style={[
            styles.card,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <Text style={[styles.cardTitle, { color: theme.textPrimary }]} accessibilityRole="header">
            Background Sync
          </Text>
          <Text style={[styles.helper, { color: theme.textMuted }]}>
            Uses Expo background tasks when available and falls back to
            foreground refreshes when periodic work is unavailable.
          </Text>

          <View
            style={styles.row}
            accessibilityLabel={`Periodic Sync. ${backgroundSyncSettings.enabled ? 'Enabled' : 'Disabled'}. Refresh notifications and recent activity without opening the app.`}
            accessibilityRole="none"
          >
            <View style={styles.rowCopy} accessibilityElementsHidden={true} importantForAccessibility="no">
              <Text style={[styles.label, { color: theme.textPrimary }]}>
                Periodic Sync
              </Text>
              <Text style={[styles.helper, { color: theme.textMuted }]}>
                Refresh notifications and recent activity without opening the
                app.
              </Text>
            </View>
            <Switch
              value={backgroundSyncSettings.enabled}
              onValueChange={(value) => {
                void setBackgroundSyncSettings((current) => ({
                  ...current,
                  enabled: value,
                }));
              }}
              accessibilityLabel={`Periodic Sync toggle, currently ${backgroundSyncSettings.enabled ? 'on' : 'off'}`}
              accessibilityRole="switch"
              accessibilityState={{ checked: backgroundSyncSettings.enabled }}
            />
          </View>

          <View
            style={styles.row}
            accessibilityLabel={`Wi-Fi Only. ${backgroundSyncSettings.wifiOnly ? 'Enabled' : 'Disabled'}. Skip background work on mobile data for better battery life.`}
            accessibilityRole="none"
          >
            <View style={styles.rowCopy} accessibilityElementsHidden={true} importantForAccessibility="no">
              <Text style={[styles.label, { color: theme.textPrimary }]}>
                Wi-Fi Only
              </Text>
              <Text style={[styles.helper, { color: theme.textMuted }]}>
                Skip background work on mobile data for better battery life.
              </Text>
            </View>
            <Switch
              value={backgroundSyncSettings.wifiOnly}
              onValueChange={(value) => {
                void setBackgroundSyncSettings((current) => ({
                  ...current,
                  wifiOnly: value,
                }));
              }}
              accessibilityLabel={`Wi-Fi Only toggle, currently ${backgroundSyncSettings.wifiOnly ? 'on' : 'off'}`}
              accessibilityRole="switch"
              accessibilityState={{ checked: backgroundSyncSettings.wifiOnly }}
            />
          </View>

          <Text style={[styles.subheading, { color: theme.textPrimary }]} accessibilityRole="header">
            Sync Frequency
          </Text>
          <View style={styles.optionGroup}>
            {FREQUENCY_OPTIONS.map((option) => {
              const active = option.value === backgroundSyncSettings.frequency;
              return (
                <Pressable
                  key={option.value}
                  style={[
                    styles.optionCard,
                    {
                      borderColor: active
                        ? theme.buttonPrimaryBg
                        : theme.border,
                      backgroundColor: active
                        ? theme.chipActiveBg
                        : theme.background,
                    },
                  ]}
                  onPress={() => {
                    void setBackgroundSyncSettings((current) => ({
                      ...current,
                      frequency: option.value,
                    }));
                  }}
                  accessibilityLabel={`Sync frequency: ${option.label}. ${option.helper}. ${active ? 'Currently selected' : 'Not selected'}.`}
                  accessibilityRole="radio"
                  accessibilityState={{ selected: active }}
                  accessibilityHint={`Double-tap to set sync frequency to ${option.label}`}
                >
                  <Text
                    style={[
                      styles.optionTitle,
                      {
                        color: active
                          ? theme.chipActiveText
                          : theme.textPrimary,
                      },
                    ]}
                    accessibilityElementsHidden={true}
                    importantForAccessibility="no"
                  >
                    {option.label}
                  </Text>
                  <Text
                    style={[styles.optionHelper, { color: theme.textMuted }]}
                    accessibilityElementsHidden={true}
                    importantForAccessibility="no"
                  >
                    {option.helper}
                  </Text>
                </Pressable>
              );
            })}
          </View>

          <View
            style={[
              styles.statusCard,
              {
                backgroundColor: theme.surfaceElevated,
                borderColor: theme.borderLight,
              },
            ]}
            accessibilityLabel={`${backgroundTaskAvailable
              ? "Native background scheduling is available on this build."
              : "This build will fall back to foreground refreshes if native background scheduling is unavailable."
            }. ${isSyncing
              ? "Syncing now."
              : lastSyncedAt
                ? `Last successful sync: ${new Date(lastSyncedAt).toLocaleString()}.`
                : "No successful sync recorded yet."
            }`}
          >
            <Text
              style={[styles.statusText, { color: theme.textPrimary }]}
              accessibilityElementsHidden={true}
              importantForAccessibility="no"
            >
              {backgroundTaskAvailable
                ? "Native background scheduling is available on this build."
                : "This build will fall back to foreground refreshes if native background scheduling is unavailable."}
            </Text>
            <Text
              style={[styles.statusSubtext, { color: theme.textMuted }]}
              accessibilityElementsHidden={true}
              importantForAccessibility="no"
            >
              {isSyncing
                ? "Syncing now..."
                : lastSyncedAt
                  ? `Last successful sync: ${new Date(lastSyncedAt).toLocaleString()}`
                  : "No successful sync recorded yet."}
            </Text>
            <Pressable
              style={[
                styles.syncNowButton,
                { backgroundColor: theme.buttonPrimaryBg },
              ]}
              onPress={() => {
                void syncNow();
              }}
              disabled={isSyncing}
              accessibilityLabel={`Force a background sync now. ${isSyncing ? 'Sync in progress, button disabled.' : 'Tap to start sync.'}`}
              accessibilityRole="button"
              accessibilityState={{ disabled: isSyncing }}
            >
              <Text
                style={[
                  styles.syncNowButtonText,
                  { color: theme.buttonPrimaryText },
                ]}
                accessibilityElementsHidden={true}
                importantForAccessibility="no"
              >
                Sync Now
              </Text>
            </Pressable>
          </View>
        </View>

        <View
          style={[
            styles.card,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <Text style={[styles.cardTitle, { color: theme.textPrimary }]} accessibilityRole="header">Build Info</Text>

          <View style={styles.row} accessibilityLabel={`Version: ${APP_VERSION}`}>
            <Text style={[styles.label, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Version</Text>
            <Text style={[styles.helper, { color: theme.textMuted }]} accessibilityElementsHidden={true} importantForAccessibility="no"> 
              {APP_VERSION}
            </Text>
          </View>

          <View style={styles.row} accessibilityLabel={`Build: ${BUILD_METADATA}`}>
            <Text style={[styles.label, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Build</Text>
            <Text style={[styles.helper, { color: theme.textMuted }]} accessibilityElementsHidden={true} importantForAccessibility="no"> 
              {BUILD_METADATA}
            </Text>
          </View>

          <View
            style={styles.row}
            accessibilityLabel={`Environment: ${APP_ENVIRONMENT}${APP_ENVIRONMENT === 'staging' ? ', staging build badge displayed.' : '.'}`}
          >
            <Text style={[styles.label, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Environment</Text>
            <View style={styles.envBadgeRow} accessibilityElementsHidden={true} importantForAccessibility="no">
              {APP_ENVIRONMENT === 'staging' ? (
                <View style={[styles.envBadge, { backgroundColor: '#F3E8FF', borderColor: '#A855F7' }]}>
                  <Text style={[styles.envBadgeText, { color: '#6B21A8' }]}>STAGING</Text>
                </View>
              ) : null}
              <Text style={[styles.helper, { color: theme.textMuted }]}> 
                {APP_ENVIRONMENT}
              </Text>
            </View>
          </View>

          <View style={styles.row} accessibilityLabel={`Stellar Network: ${STELLAR_NETWORK}`}>
            <Text style={[styles.label, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Network</Text>
            <Text style={[styles.helper, { color: theme.textMuted }]} accessibilityElementsHidden={true} importantForAccessibility="no"> 
              {STELLAR_NETWORK}
            </Text>
          </View>

          {BUILD_TAG ? (
            <View style={styles.row} accessibilityLabel={`Build Tag: ${BUILD_TAG}`}>
              <Text style={[styles.label, { color: theme.textPrimary }]} accessibilityElementsHidden={true} importantForAccessibility="no">Tag</Text>
              <Text style={[styles.helper, { color: theme.textMuted }]} accessibilityElementsHidden={true} importantForAccessibility="no"> 
                {BUILD_TAG}
              </Text>
            </View>
          ) : null}
        </View>

        <View
          style={[
            styles.card,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <Text style={[styles.cardTitle, { color: theme.textPrimary }]} accessibilityRole="header">
            Feedback
          </Text>

          <Link href="/feedback" asChild>
            <Pressable
              style={styles.row}
              accessibilityLabel="Send Feedback. Report an issue or idea. Build and environment details are attached automatically."
              accessibilityRole="link"
              accessibilityHint="Double-tap to navigate to the feedback form"
            >
              <View style={styles.rowCopy} accessibilityElementsHidden={true} importantForAccessibility="no">
                <Text style={[styles.label, { color: theme.textPrimary }]}>
                  Send Feedback
                </Text>
                <Text style={[styles.helper, { color: theme.textMuted }]}>
                  Report an issue or idea. Build and environment details are
                  attached automatically.
                </Text>
              </View>
              <Text style={[styles.helper, { color: theme.textMuted }]} accessibilityElementsHidden={true} importantForAccessibility="no">→</Text>
            </Pressable>
          </Link>
        </View>

        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]} accessibilityRole="header">
            Onboarding
          </Text>
          <OnboardingResetButton />
        </View>

        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]} accessibilityRole="header">Privacy & Data</Text>
          <Pressable
            style={[
              styles.clearDataButton,
              {
                backgroundColor: theme.surface,
                borderColor: theme.status.error,
              },
            ]}
            onPress={handleClearLocalData}
            accessibilityLabel="Clear Local Data. Destructive action. Removes cached app data, signs you out, and clears secure storage. Cannot be undone."
            accessibilityRole="button"
            accessibilityHint="Double-tap to open confirmation dialog for clearing all local data"
          >
            <Text
              style={[styles.clearDataText, { color: theme.status.error }]}
              accessibilityElementsHidden={true}
              importantForAccessibility="no"
            >Clear Local Data</Text>
          </Pressable>
          <Text style={[styles.helper, { color: theme.textMuted }]}>Remove all cached and secure data, sign out, and reset the app state.</Text>
        </View>

        <EnvironmentSwitcher />

        {Platform.OS !== "web" && IS_DEBUG_BUILD ? (
          <View style={styles.section}>
            <Text style={[styles.sectionTitle, { color: theme.textPrimary }]} accessibilityRole="header">
              Debug
            </Text>
            <Link href="/notification-debug" asChild>
              <Pressable
                style={[
                  styles.debugButton,
                  { backgroundColor: theme.surface, borderColor: theme.border },
                ]}
                accessibilityLabel="Open Notification Simulator. Debug page to test notification rendering and delivery."
                accessibilityRole="link"
              >
                <Text
                  style={[styles.debugButtonText, { color: theme.textPrimary }]}
                  accessibilityElementsHidden={true}
                  importantForAccessibility="no"
                >
                  Open Notification Simulator
                </Text>
              </Pressable>
            </Link>
            <Link href="/qa-smoke-checklist" asChild>
              <Pressable
                style={[
                  styles.debugButton,
                  { backgroundColor: theme.surface, borderColor: theme.border },
                ]}
                accessibilityLabel="QA Smoke Checklist. Verification checklist for validating app features."
                accessibilityRole="link"
              >
                <Text
                  style={[styles.debugButtonText, { color: theme.textPrimary }]}
                  accessibilityElementsHidden={true}
                  importantForAccessibility="no"
                >
                  QA Smoke Checklist
                </Text>
              </Pressable>
            </Link>
            {APP_ENVIRONMENT !== "production" && (
              <Link href="/offline-queue-inspector" asChild>
                <Pressable
                  style={[
                    styles.debugButton,
                    { backgroundColor: theme.surface, borderColor: theme.border },
                  ]}
                  accessibilityLabel="Offline Queue Inspector. Debug page to view pending offline operations."
                  accessibilityRole="link"
                >
                  <Text
                    style={[styles.debugButtonText, { color: theme.textPrimary }]}
                    accessibilityElementsHidden={true}
                    importantForAccessibility="no"
                  >
                    Offline Queue Inspector
                  </Text>
                </Pressable>
              </Link>
            )}
          </View>
        ) : null}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  scrollView: { flex: 1 },
  content: {
    padding: 24,
    gap: 18,
  },
  title: { fontSize: 28, fontWeight: "700" },
  card: {
    borderRadius: 18,
    padding: 18,
    borderWidth: 1,
    gap: 16,
  },
  cardTitle: {
    fontSize: 18,
    fontWeight: "700",
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 12,
    minHeight: 48,
  },
  rowCopy: {
    flex: 1,
    gap: 4,
  },
  label: { fontSize: 16, fontWeight: "600" },
  helper: {
    fontSize: 13,
    lineHeight: 18,
  },
  subheading: {
    fontSize: 15,
    fontWeight: "700",
  },
  optionGroup: {
    gap: 10,
  },
  optionCard: {
    borderWidth: 1,
    borderRadius: 14,
    padding: 14,
  },
  optionTitle: {
    fontSize: 15,
    fontWeight: "700",
    marginBottom: 4,
  },
  optionHelper: {
    fontSize: 13,
  },
  statusCard: {
    borderWidth: 1,
    borderRadius: 14,
    padding: 14,
    gap: 8,
  },
  statusText: {
    fontSize: 14,
    fontWeight: "600",
    lineHeight: 20,
  },
  statusSubtext: {
    fontSize: 12,
    lineHeight: 18,
  },
  syncNowButton: {
    alignSelf: "flex-start",
    borderRadius: 10,
    paddingVertical: 10,
    paddingHorizontal: 14,
  },
  syncNowButtonText: {
    fontSize: 13,
    fontWeight: "700",
  },
  clearDataButton: {
    borderWidth: 1,
    borderRadius: 14,
    paddingVertical: 14,
    paddingHorizontal: 16,
    alignItems: "center",
  },
  clearDataText: {
    fontSize: 15,
    fontWeight: "700",
  },
  section: {
    gap: 12,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: "600",
  },
  debugButton: {
    borderWidth: 1,
    borderRadius: 12,
    paddingVertical: 12,
    paddingHorizontal: 14,
    minHeight: 48,
    justifyContent: "center",
  },
  debugButtonText: {
    fontSize: 14,
    fontWeight: "600",
  },
  envBadgeRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  envBadge: {
    borderWidth: 1,
    borderRadius: 6,
    paddingHorizontal: 8,
    paddingVertical: 2,
  },
  envBadgeText: {
    fontSize: 11,
    fontWeight: "800",
    letterSpacing: 0.5,
  },
});
