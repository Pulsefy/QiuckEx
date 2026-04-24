import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import { scheduleNotificationSimulation } from "../services/notification-simulator";
import { PUSH_NOTIFICATION_TYPES } from "../types/push-notification";
import { useTheme } from "../src/theme/ThemeContext";

export default function NotificationDebugScreen() {
  const { theme } = useTheme();

  return (
    <SafeAreaView
      style={[styles.container, { backgroundColor: theme.background }]}
      edges={["top", "bottom"]}
    >
      <View style={styles.content}>
        <Text style={[styles.title, { color: theme.textPrimary }]}>
          Notification Simulator
        </Text>
        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
          Tap a button to trigger a local push notification and validate deep link routing.
        </Text>

        <SimulatorButton
          label="Simulate Transaction Notification"
          themeColor={theme.buttonPrimaryBg}
          textColor={theme.buttonPrimaryText}
          onPress={() =>
            scheduleNotificationSimulation({
              type: PUSH_NOTIFICATION_TYPES.transactionDetail,
              transactionId: "tx_demo_12345",
              txHash: "txhash_demo_12345",
              amount: "42.00",
              asset: "XLM",
              status: "Success",
            })
          }
        />

        <SimulatorButton
          label="Simulate Escrow Notification"
          themeColor={theme.buttonPrimaryBg}
          textColor={theme.buttonPrimaryText}
          onPress={() =>
            scheduleNotificationSimulation({
              type: PUSH_NOTIFICATION_TYPES.escrowDetail,
              escrowId: "escrow_demo_987",
              status: "funded",
            })
          }
        />

        <SimulatorButton
          label="Simulate Listing Notification"
          themeColor={theme.buttonPrimaryBg}
          textColor={theme.buttonPrimaryText}
          onPress={() =>
            scheduleNotificationSimulation({
              type: PUSH_NOTIFICATION_TYPES.listingDetail,
              listingId: "listing_demo_456",
              sellerId: "seller_001",
            })
          }
        />
      </View>
    </SafeAreaView>
  );
}

function SimulatorButton({
  label,
  onPress,
  themeColor,
  textColor,
}: {
  label: string;
  onPress: () => void;
  themeColor: string;
  textColor: string;
}) {
  return (
    <Pressable style={[styles.button, { backgroundColor: themeColor }]} onPress={onPress}>
      <Text style={[styles.buttonText, { color: textColor }]}>{label}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  content: {
    padding: 24,
    gap: 14,
  },
  title: {
    fontSize: 24,
    fontWeight: "700",
  },
  subtitle: {
    fontSize: 14,
    lineHeight: 20,
    marginBottom: 8,
  },
  button: {
    borderRadius: 12,
    paddingVertical: 14,
    paddingHorizontal: 16,
  },
  buttonText: {
    fontSize: 15,
    fontWeight: "700",
  },
});
