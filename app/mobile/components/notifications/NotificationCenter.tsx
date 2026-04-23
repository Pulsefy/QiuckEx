import React from "react";
import {
  FlatList,
  Modal,
  Pressable,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { useTranslation } from 'react-i18next';
import { Ionicons } from "@expo/vector-icons";

import { useTheme } from "../../src/theme/ThemeContext";
import { useNotifications } from "./NotificationContext";

export const NotificationCenter: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { notifications, unreadCount, markAllRead } = useNotifications();
  const { theme } = useTheme();
  const [open, setOpen] = React.useState(false);

  const openCenter = React.useCallback(() => {
    setOpen(true);
    markAllRead();
  }, [markAllRead]);

  return (
    <>
      <Pressable style={styles.bell} onPress={openCenter}>
        <Ionicons
          name="notifications-outline"
          size={24}
          color={theme.textPrimary}
        />
        {unreadCount > 0 ? (
          <View
            style={[styles.badge, { backgroundColor: theme.status.error }]}
          >
            <Text
              style={[styles.badgeText, { color: theme.buttonDangerText }]}
            >
              {unreadCount}
            </Text>
          </View>
        ) : null}
      </Pressable>

      <Modal
        visible={open}
        animationType="slide"
        onRequestClose={() => setOpen(false)}
      >
        <View
          style={[
            styles.modalHeader,
            { borderColor: theme.border, backgroundColor: theme.background },
          ]}
        >
          <Text style={[styles.modalTitle, { color: theme.textPrimary }]}>
            Notifications
          </Text>
        <View style={[styles.modalHeader, { borderColor: theme.border, backgroundColor: theme.background }]}>
          <Text style={[styles.modalTitle, { color: theme.textPrimary }]}>{t('notificationsTitle')}</Text>
          <Pressable onPress={() => setOpen(false)}>
            <Text style={[styles.close, { color: theme.link }]}>{t('close')}</Text>
          </Pressable>
        </View>

        <FlatList
          data={notifications}
          keyExtractor={(item) => item.id}
          contentContainerStyle={styles.list}
          style={{ backgroundColor: theme.background }}
          renderItem={({ item }) => (
            <View
              style={[
                styles.item,
                { borderColor: theme.borderLight },
                !item.read && { backgroundColor: theme.surfaceElevated },
              ]}
            >
              <Text style={[styles.itemTitle, { color: theme.textPrimary }]}>
                {item.direction === "outgoing" ? "Sent" : "Received"}{" "}
                {item.amount} {item.asset ?? ""}
              </Text>
              <Text
                style={[styles.itemSubtitle, { color: theme.textSecondary }]}
              >
                {item.direction === "outgoing" ? "To" : "From"}{" "}
                {item.sender ? shorten(item.sender) : "Unknown"} •{" "}
                {new Date(item.receivedAt).toLocaleString()}
              <Text style={[styles.itemSubtitle, { color: theme.textSecondary }]}>
                {item.sender ? `${shorten(item.sender)}` : ""} •{" "}
                {new Date(item.receivedAt).toLocaleString(i18n.language || 'en')}
              </Text>
              {item.memo ? (
                <Text style={[styles.itemMeta, { color: theme.textMuted }]}>
                  Memo: {item.memo}
                </Text>
              ) : null}
            </View>
          )}
          ListEmptyComponent={() => (
            <View style={styles.empty}>
              <Text
                style={[styles.emptyText, { color: theme.textSecondary }]}
              >
                No notifications
              </Text>
              <Text style={[styles.emptyText, { color: theme.textSecondary }]}>{t('noNotifications')}</Text>
            </View>
          )}
        />
      </Modal>
    </>
  );
};

function shorten(value: string) {
  if (!value) return "";
  if (value.length <= 10) return value;
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
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
  item: {
    paddingVertical: 12,
    paddingHorizontal: 12,
    borderBottomWidth: 1,
    borderRadius: 12,
    marginBottom: 8,
  },
  itemTitle: { fontWeight: "700" },
  itemSubtitle: { marginTop: 4 },
  itemMeta: { marginTop: 6, fontSize: 12 },
  empty: { padding: 40, alignItems: "center" },
  emptyText: {},
});

export default NotificationCenter;
