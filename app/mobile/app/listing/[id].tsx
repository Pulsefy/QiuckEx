import React from "react";
import { StyleSheet, Text, View } from "react-native";
import { useLocalSearchParams } from "expo-router";
import { SafeAreaView } from "react-native-safe-area-context";

import { useTheme } from "../../src/theme/ThemeContext";

export default function ListingDetailScreen() {
  const { theme } = useTheme();
  const params = useLocalSearchParams<{ id: string; sellerId?: string }>();

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <View style={[styles.card, { backgroundColor: theme.surface, borderColor: theme.border }]}>
        <Text style={[styles.title, { color: theme.textPrimary }]}>Listing Detail</Text>
        <Text style={[styles.row, { color: theme.textSecondary }]}>Listing ID: {params.id}</Text>
        <Text style={[styles.row, { color: theme.textSecondary }]}>
          Seller ID: {params.sellerId ?? "unknown"}
        </Text>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24 },
  card: {
    borderWidth: 1,
    borderRadius: 16,
    padding: 16,
    gap: 10,
  },
  title: {
    fontSize: 22,
    fontWeight: "700",
  },
  row: {
    fontSize: 15,
  },
});
