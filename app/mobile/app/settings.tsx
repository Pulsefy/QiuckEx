import { Link } from "expo-router";
import React from "react";
import {
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
import {
  SYNC_INTERVALS_MINUTES,
  type SyncFrequency,
} from "../services/background-sync";
import { useTheme } from "../src/theme/ThemeContext";

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
  const { theme } = useTheme();
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

  return (
    <SafeAreaView
      style={[styles.container, { backgroundColor: theme.background }]}
    >
      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.content}
        showsVerticalScrollIndicator={false}
      >
        <Text style={[styles.title, { color: theme.textPrimary }]}>
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
          <Text style={[styles.cardTitle, { color: theme.textPrimary }]}>
            Security
          </Text>

          <Link href="/security-center" asChild>
            <Pressable style={styles.row}>
              <View style={styles.rowCopy}>
                <Text style={[styles.label, { color: theme.textPrimary }]}>
                  Security Center
                </Text>
                <Text style={[styles.helper, { color: theme.textMuted }]}>
                  Review your security posture and settings.
                </Text>
              </View>
              <Text style={[styles.helper, { color: theme.textMuted }]}>→</Text>
            </Pressable>
          </Link>
        </View>

        <View
          style={[
            styles.card,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <Text style={[styles.cardTitle, { color: theme.textPrimary }]}>
            Notifications
          </Text>

          <View style={styles.row}>
            <View style={styles.rowCopy}>
              <Text style={[styles.label, { color: theme.textPrimary }]}>
                Sound Effects
              </Text>
              <Text style={[styles.helper, { color: theme.textMuted }]}>
                Play a short tone when a new synced notification appears.
              </Text>
            </View>
            <Switch value={soundEnabled} onValueChange={setSoundEnabled} />
          </View>

          <View style={styles.row}>
            <View style={styles.rowCopy}>
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
            />
          </View>
        </View>

        <View
          style={[
            styles.card,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <Text style={[styles.cardTitle, { color: theme.textPrimary }]}>
            Background Sync
          </Text>
          <Text style={[styles.helper, { color: theme.textMuted }]}>
            Uses Expo background tasks when available and falls back to
            foreground refreshes when periodic work is unavailable.
          </Text>

          <View style={styles.row}>
            <View style={styles.rowCopy}>
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
            />
          </View>

          <View style={styles.row}>
            <View style={styles.rowCopy}>
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
            />
          </View>

          <Text style={[styles.subheading, { color: theme.textPrimary }]}>
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
                  >
                    {option.label}
                  </Text>
                  <Text
                    style={[styles.optionHelper, { color: theme.textMuted }]}
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
          >
            <Text style={[styles.statusText, { color: theme.textPrimary }]}>
              {backgroundTaskAvailable
                ? "Native background scheduling is available on this build."
                : "This build will fall back to foreground refreshes if native background scheduling is unavailable."}
            </Text>
            <Text style={[styles.statusSubtext, { color: theme.textMuted }]}>
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
            >
              <Text
                style={[
                  styles.syncNowButtonText,
                  { color: theme.buttonPrimaryText },
                ]}
              >
                Sync Now
              </Text>
            </Pressable>
          </View>
        </View>

        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
            Onboarding
          </Text>
          <OnboardingResetButton />
        </View>

        {Platform.OS !== "web" ? (
          <View style={styles.section}>
            <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
              Debug
            </Text>
            <Link href="/notification-debug" asChild>
              <Pressable
                style={[
                  styles.debugButton,
                  { backgroundColor: theme.surface, borderColor: theme.border },
                ]}
              >
                <Text
                  style={[styles.debugButtonText, { color: theme.textPrimary }]}
                >
                  Open Notification Simulator
                </Text>
              </Pressable>
            </Link>
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
  },
  debugButtonText: {
    fontSize: 14,
    fontWeight: "600",
  },
});
