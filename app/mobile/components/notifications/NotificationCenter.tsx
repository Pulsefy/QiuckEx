import React from "react";
import {
  Modal,
  Pressable,
  StyleSheet,
  Text,
  View,
  FlatList,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useNotifications } from "./NotificationContext";
import { useTheme } from "../../src/theme/ThemeContext";

export const NotificationCenter: React.FC = () => {
  const { notifications, unreadCount, markAllRead } = useNotifications();
  const { theme } = useTheme();
  const [open, setOpen] = React.useState(false);

  const openCenter = () => {
    setOpen(true);
    markAllRead();
  };

  return (
    <>
      <Pressable style={styles.bell} onPress={openCenter}>
        <Ionicons name="notifications-outline" size={24} color={theme.textPrimary} />
        {unreadCount > 0 ? (
          <View style={[styles.badge, { backgroundColor: theme.status.error }]}>
            <Text style={[styles.badgeText, { color: theme.buttonDangerText }]}>{unreadCount}</Text>
          </View>
        ) : null}
      </Pressable>

      <Modal
        visible={open}
        animationType="slide"
        onRequestClose={() => setOpen(false)}
      >
        <View style={[styles.modalHeader, { borderColor: theme.border, backgroundColor: theme.background }]}>
          <Text style={[styles.modalTitle, { color: theme.textPrimary }]}>Notifications</Text>
          <Pressable onPress={() => setOpen(false)}>
            <Text style={[styles.close, { color: theme.link }]}>Close</Text>
          </Pressable>
        </View>

        <FlatList
          data={notifications}
          keyExtractor={(i) => i.id}
          contentContainerStyle={styles.list}
          style={{ backgroundColor: theme.background }}
          renderItem={({ item }) => (
            <View style={[styles.item, { borderColor: theme.borderLight }]}>
              <Text style={[styles.itemTitle, { color: theme.textPrimary }]}>
                💰 {item.amount} {item.asset ?? ""}
              </Text>
              <Text style={[styles.itemSubtitle, { color: theme.textSecondary }]}>
                {item.sender ? `${shorten(item.sender)}` : ""} •{" "}
                {new Date(item.receivedAt).toLocaleString()}
              </Text>
            </View>
          )}
          ListEmptyComponent={() => (
            <View style={styles.empty}>
              <Text style={[styles.emptyText, { color: theme.textSecondary }]}>No notifications</Text>
            </View>
          )}
        />
      </Modal>
    </>
  );
};

function shorten(s: string) {
  if (!s) return "";
  if (s.length <= 10) return s;
  return `${s.slice(0, 6)}...${s.slice(-4)}`;
}

const styles = StyleSheet.create({
  bell: { marginRight: 12 },
  badge: {
    position: "absolute",
    right: -6,
    top: -6,
    borderRadius: 9,
    minWidth: 18,
    paddingHorizontal: 4,
    alignItems: "center",
    justifyContent: "center",
  },
  badgeText: { fontSize: 12, fontWeight: "700" },
  modalHeader: {
    padding: 16,
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    borderBottomWidth: 1,
  },
  modalTitle: { fontSize: 18, fontWeight: "700" },
  close: {},
  list: { padding: 16 },
  item: { paddingVertical: 12, borderBottomWidth: 1 },
  itemTitle: { fontWeight: "700" },
  itemSubtitle: { marginTop: 4 },
  empty: { padding: 40, alignItems: "center" },
  emptyText: {},
});

export default NotificationCenter;
