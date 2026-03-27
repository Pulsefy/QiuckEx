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

export const NotificationCenter: React.FC = () => {
  const { notifications, unreadCount, markAllRead } = useNotifications();
  const [open, setOpen] = React.useState(false);

  const openCenter = () => {
    setOpen(true);
    markAllRead();
  };

  return (
    <>
      <Pressable style={styles.bell} onPress={openCenter}>
        <Ionicons name="notifications-outline" size={24} color="#111827" />
        {unreadCount > 0 ? (
          <View style={styles.badge}>
            <Text style={styles.badgeText}>{unreadCount}</Text>
          </View>
        ) : null}
      </Pressable>

      <Modal
        visible={open}
        animationType="slide"
        onRequestClose={() => setOpen(false)}
      >
        <View style={styles.modalHeader}>
          <Text style={styles.modalTitle}>Notifications</Text>
          <Pressable onPress={() => setOpen(false)}>
            <Text style={styles.close}>Close</Text>
          </Pressable>
        </View>

        <FlatList
          data={notifications}
          keyExtractor={(i) => i.id}
          contentContainerStyle={styles.list}
          renderItem={({ item }) => (
            <View style={styles.item}>
              <Text style={styles.itemTitle}>
                💰 {item.amount} {item.asset ?? ""}
              </Text>
              <Text style={styles.itemSubtitle}>
                {item.sender ? `${shorten(item.sender)}` : ""} •{" "}
                {new Date(item.receivedAt).toLocaleString()}
              </Text>
            </View>
          )}
          ListEmptyComponent={() => (
            <View style={styles.empty}>
              <Text style={styles.emptyText}>No notifications</Text>
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
    backgroundColor: "#EF4444",
    borderRadius: 9,
    minWidth: 18,
    paddingHorizontal: 4,
    alignItems: "center",
    justifyContent: "center",
  },
  badgeText: { color: "#fff", fontSize: 12, fontWeight: "700" },
  modalHeader: {
    padding: 16,
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    borderBottomWidth: 1,
    borderColor: "#eee",
  },
  modalTitle: { fontSize: 18, fontWeight: "700" },
  close: { color: "#2563EB" },
  list: { padding: 16 },
  item: { paddingVertical: 12, borderBottomWidth: 1, borderColor: "#f3f4f6" },
  itemTitle: { fontWeight: "700" },
  itemSubtitle: { color: "#6B7280", marginTop: 4 },
  empty: { padding: 40, alignItems: "center" },
  emptyText: { color: "#6B7280" },
});

export default NotificationCenter;
