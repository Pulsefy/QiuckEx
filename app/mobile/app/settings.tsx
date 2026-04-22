import React from "react";
import { SafeAreaView } from "react-native-safe-area-context";
import { View, Text, StyleSheet, Switch } from "react-native";
import { useNotifications } from "../components/notifications/NotificationContext";
import OnboardingResetButton from "../components/onboarding/OnboardingResetButton";

export default function SettingsScreen() {
  const { soundEnabled, setSoundEnabled } = useNotifications();

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.title}>Settings</Text>

        <View style={styles.row}>
          <Text style={styles.label}>🔔 Sound Effects</Text>
          <Switch value={soundEnabled} onValueChange={setSoundEnabled} />
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Onboarding</Text>
          <OnboardingResetButton />
        </View>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#fff" },
  content: { padding: 24 },
  title: { fontSize: 28, fontWeight: "700", marginBottom: 16 },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderColor: "#f3f4f6",
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
