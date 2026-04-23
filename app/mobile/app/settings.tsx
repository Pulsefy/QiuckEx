import React from "react";
import { SafeAreaView } from "react-native-safe-area-context";
import { View, Text, StyleSheet, Switch, ScrollView } from "react-native";
import { useNotifications } from "../components/notifications/NotificationContext";
import OnboardingResetButton from "../components/onboarding/OnboardingResetButton";
import { ThemeSelector } from "../components/ThemeSelector";
import { LocaleSwitcher } from "../components/LocaleSwitcher";
import { useTheme } from "../src/theme/ThemeContext";

export default function SettingsScreen() {
  const { soundEnabled, setSoundEnabled } = useNotifications();
  const { theme } = useTheme();

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <ScrollView style={styles.scrollView} showsVerticalScrollIndicator={false}>
        <View style={styles.content}>
          <Text style={[styles.title, { color: theme.textPrimary }]}>Settings</Text>

          {/* ── Theme Selector ─────────────────────────────────── */}
          <ThemeSelector />

          <View style={styles.spacer} />

          {/* ── Locale Switcher ─────────────────────────────────── */}
          <LocaleSwitcher />

          <View style={styles.spacer} />

          {/* ── Sound settings ─────────────────────────────────── */}
          <View style={[styles.card, { backgroundColor: theme.surface, borderColor: theme.border }]}>
            <View style={styles.row}>
              <Text style={[styles.label, { color: theme.textPrimary }]}>🔔 Sound Effects</Text>
              <Switch value={soundEnabled} onValueChange={setSoundEnabled} />
            </View>
          </View>
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Onboarding</Text>
          <OnboardingResetButton />
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  scrollView: { flex: 1 },
  content: { padding: 24 },
  title: { fontSize: 28, fontWeight: "700", marginBottom: 20 },
  spacer: { height: 16 },
  card: {
    borderRadius: 16,
    padding: 16,
    borderWidth: 1,
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 12,
  },
  label: { fontSize: 16 },
  section: {
    marginTop: 24,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: "600",
    marginBottom: 12,
    color: "#374151",
  },
});
