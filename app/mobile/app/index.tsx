import { Link, useRouter } from "expo-router";
import React, { useEffect } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import NotificationCenter from "../components/notifications/NotificationCenter";
import { useNotifications } from "../components/notifications/NotificationContext";
import { useOnboarding } from "../hooks/useOnboarding";
import { useTheme } from "../src/theme/ThemeContext";

export default function HomeScreen() {
  const router = useRouter();
  const { theme } = useTheme();
  const { hasCompletedOnboarding, isLoading } = useOnboarding();
  const {
    currentAccountId,
    isSyncing,
    lastSyncedAt,
    recentActivity,
    syncNow,
  } = useNotifications();
  useEffect(() => {
    if (!isLoading && !hasCompletedOnboarding) {
      router.replace("/onboarding");
    }
  }, [hasCompletedOnboarding, isLoading, router]);

  if (isLoading || !hasCompletedOnboarding) {
    return null;
  }

  return (
    <SafeAreaView
      style={[styles.container, { backgroundColor: theme.background }]}
    >
      <ScrollView
        contentContainerStyle={styles.content}
        showsVerticalScrollIndicator={false}
      >
        <View style={styles.headerRow}>
          <View style={styles.headerCopy}>
            <Text style={[styles.title, { color: theme.textPrimary }]}>
              QuickEx
            </Text>
            <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
              Notifications, badges, and recent activity stay fresh even when
              you are not actively using the app.
            </Text>
          </View>
          <NotificationCenter />
        </View>

        <View
          style={[
            styles.heroCard,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <Text style={[styles.heroTitle, { color: theme.textPrimary }]}>
            Background Sync
          </Text>
          <Text style={[styles.heroText, { color: theme.textSecondary }]}>
            {currentAccountId
              ? `Watching ${shorten(currentAccountId)} for new activity.`
              : "Connect a wallet to start syncing activity and badge counts."}
          </Text>
          <View style={styles.heroMetaRow}>
            <Text style={[styles.heroMeta, { color: theme.textMuted }]}>
              {isSyncing
                ? "Syncing now..."
                : lastSyncedAt
                  ? `Last synced ${new Date(lastSyncedAt).toLocaleTimeString()}`
                  : "Not synced yet"}
            </Text>
            <Pressable
              style={[
                styles.syncButton,
                { backgroundColor: theme.buttonPrimaryBg },
              ]}
              onPress={() => {
                void syncNow();
              }}
            >
              <Text
                style={[
                  styles.syncButtonText,
                  { color: theme.buttonPrimaryText },
                ]}
              >
                Sync Now
              </Text>
            </Pressable>
          </View>
        </View>

        <View
          style={[
            styles.sectionCard,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <View style={styles.sectionHeader}>
            <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
              Recent Activity
            </Text>
            <Link
              href={{
                pathname: "/transactions",
                params: currentAccountId
                  ? { accountId: currentAccountId }
                  : undefined,
              }}
              asChild
            >
              <Pressable>
                <Text style={[styles.linkText, { color: theme.link }]}>
                  View All
                </Text>
              </Pressable>
            </Link>
          </View>

          {recentActivity.length > 0 ? (
            recentActivity.slice(0, 5).map((item) => {
              const incoming = item.destination === currentAccountId;
              return (
                <View
                  key={item.pagingToken}
                  style={[
                    styles.activityRow,
                    { borderColor: theme.borderLight },
                  ]}
                >
                  <View style={styles.activityCopy}>
                    <Text
                      style={[styles.activityTitle, { color: theme.textPrimary }]}
                    >
                      {incoming ? "Received" : "Sent"} {formatAmount(item.amount)}{" "}
                      {assetCode(item.asset)}
                    </Text>
                    <Text
                      style={[
                        styles.activitySubtitle,
                        { color: theme.textSecondary },
                      ]}
                    >
                      {incoming ? "From" : "To"}{" "}
                      {shorten(
                        incoming ? item.source ?? "" : item.destination ?? "",
                      )}{" "}
                      • {new Date(item.timestamp).toLocaleString()}
                    </Text>
                  </View>
                </View>
              );
            })
          ) : (
            <Text style={[styles.emptyState, { color: theme.textSecondary }]}>
              No recent activity yet. Connect a wallet and background sync will
              keep this list warm.
            </Text>
          )}
        </View>

        <View style={styles.buttonGroup}>
          <NavButton href="/scan-to-pay" label="Scan to Pay" />
          <NavButton href="/wallet-connect" label="Connect Wallet" />
          <NavButton href="/quick-receive" label="Quick Receive" />
          <NavButton href="/contacts" label="Contacts" />
          <NavButton href="/settings" label="Settings" secondary />
          <NavButton href="/security" label="Security Settings" secondary />
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

function NavButton({
  href,
  label,
  secondary = false,
}: {
  href: string;
  label: string;
  secondary?: boolean;
}) {
  const { theme } = useTheme();

  return (
    <Link href={href as never} asChild>
      <Pressable
        style={[
          styles.navButton,
          secondary
            ? {
                backgroundColor: theme.surface,
                borderColor: theme.buttonSecondaryBorder,
                borderWidth: 1,
              }
            : { backgroundColor: theme.buttonPrimaryBg },
        ]}
      >
        <Text
          style={[
            styles.navButtonText,
            secondary
              ? { color: theme.buttonSecondaryText }
              : { color: theme.buttonPrimaryText },
          ]}
        >
          {label}
        </Text>
      </Pressable>
    </Link>
  );
}

function assetCode(asset: string) {
  const separator = asset.indexOf(":");
  return separator === -1 ? asset : asset.slice(0, separator);
}

function formatAmount(amount: string) {
  const value = Number(amount);
  if (Number.isNaN(value)) return amount;
  return value.toFixed(2);
}

function shorten(value: string) {
  if (!value) return "Unknown";
  if (value.length <= 12) return value;
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  content: {
    padding: 24,
    gap: 18,
  },
  headerRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: 12,
  },
  headerCopy: {
    flex: 1,
  },
  title: {
    fontSize: 36,
    fontWeight: "800",
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 16,
    lineHeight: 22,
  },
  heroCard: {
    borderRadius: 20,
    borderWidth: 1,
    padding: 18,
    gap: 10,
  },
  heroTitle: {
    fontSize: 20,
    fontWeight: "700",
  },
  heroText: {
    fontSize: 14,
    lineHeight: 20,
  },
  heroMetaRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 12,
  },
  heroMeta: {
    flex: 1,
    fontSize: 12,
  },
  syncButton: {
    borderRadius: 10,
    paddingVertical: 10,
    paddingHorizontal: 14,
  },
  syncButtonText: {
    fontSize: 13,
    fontWeight: "700",
  },
  sectionCard: {
    borderRadius: 20,
    borderWidth: 1,
    padding: 18,
  },
  sectionHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 10,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: "700",
  },
  linkText: {
    fontSize: 13,
    fontWeight: "700",
  },
  activityRow: {
    borderBottomWidth: 1,
    paddingVertical: 12,
  },
  activityCopy: {
    gap: 4,
  },
  activityTitle: {
    fontSize: 15,
    fontWeight: "700",
  },
  activitySubtitle: {
    fontSize: 13,
    lineHeight: 18,
  },
  emptyState: {
    fontSize: 14,
    lineHeight: 20,
  },
  buttonGroup: {
    gap: 12,
    marginBottom: 16,
  },
  navButton: {
    paddingVertical: 16,
    paddingHorizontal: 18,
    borderRadius: 14,
    alignItems: "center",
  },
  navButtonText: {
    fontSize: 16,
    fontWeight: "700",
  },
});
