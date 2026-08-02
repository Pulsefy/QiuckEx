import React from 'react';
import {
  View,
  Text,
  FlatList,
  TouchableOpacity,
  StyleSheet,
  RefreshControl,
} from 'react-native';
import { useTheme } from '../hooks/useTheme';
import { themeTokens } from '../theme/tokens';

type NotificationType = 'payment_received' | 'payment_sent' | 'system';

interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
  amount?: string;
  asset?: string;
}

const MOCK_NOTIFICATIONS: Notification[] = [
  {
    id: '1',
    type: 'payment_received',
    title: 'Payment Received',
    message: 'Alice sent you a payment',
    timestamp: '2 min ago',
    read: false,
    amount: '50.00',
    asset: 'USDC',
  },
  {
    id: '2',
    type: 'payment_sent',
    title: 'Payment Sent',
    message: 'You paid Bob for design work',
    timestamp: '1 hour ago',
    read: true,
    amount: '120.00',
    asset: 'XLM',
  },
  {
    id: '3',
    type: 'system',
    title: 'Welcome to QuickEx',
    message: 'Your account is ready. Start receiving payments!',
    timestamp: '2 days ago',
    read: true,
  },
];

export function NotificationScreen() {
  const { color, isDark, tokens } = useTheme();
  const [refreshing, setRefreshing] = React.useState(false);
  const [notifications, setNotifications] = React.useState(MOCK_NOTIFICATIONS);

  const styles = themedStyles({ color, isDark, tokens });

  const onRefresh = React.useCallback(() => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 1500);
  }, []);

  const markAsRead = (id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );
  };

  const renderItem = ({ item }: { item: Notification }) => (
    <NotificationItem
      notification={item}
      onPress={() => markAsRead(item.id)}
    />
  );

  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Notifications</Text>
        {unreadCount > 0 && (
          <View style={styles.badge}>
            <Text style={styles.badgeText}>{unreadCount}</Text>
          </View>
        )}
      </View>

      {/* Notification List */}
      <FlatList
        data={notifications}
        renderItem={renderItem}
        keyExtractor={(item) => item.id}
        contentContainerStyle={styles.listContent}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={onRefresh}
            tintColor={color(tokens.action.primary)}
            colors={[color(tokens.action.primary)]}
          />
        }
        ListEmptyComponent={
          <View style={styles.emptyState}>
            <Text style={styles.emptyIcon}>🔔</Text>
            <Text style={styles.emptyTitle}>No notifications yet</Text>
            <Text style={styles.emptyDesc}>
              When you receive payments or updates, they'll appear here.
            </Text>
          </View>
        }
      />
    </View>
  );
}

function NotificationItem({
  notification,
  onPress,
}: {
  notification: Notification;
  onPress: () => void;
}) {
  const { color, tokens } = useTheme();

  const typeConfig = {
    payment_received: { icon: '💰', color: tokens.semantic.success },
    payment_sent: { icon: '↗️', color: tokens.semantic.pending },
    system: { icon: '🔔', color: tokens.action.primary },
  };

  const config = typeConfig[notification.type];

  return (
    <TouchableOpacity
      style={[
        itemStyles.container,
        {
          backgroundColor: notification.read
            ? color(tokens.surface)
            : color(tokens.state.highlight),
        },
      ]}
      onPress={onPress}
      activeOpacity={0.7}
    >
      {/* Unread Indicator */}
      {!notification.read && (
        <View
          style={[
            itemStyles.unreadDot,
            { backgroundColor: color(tokens.action.primary) },
          ]}
        />
      )}

      {/* Icon */}
      <View
        style={[
          itemStyles.iconContainer,
          { backgroundColor: color(tokens.surfaceElevated) },
        ]}
      >
        <Text style={itemStyles.icon}>{config.icon}</Text>
      </View>

      {/* Content */}
      <View style={itemStyles.content}>
        <View style={itemStyles.row}>
          <Text
            style={[
              itemStyles.title,
              {
                color: color(tokens.text.primary),
                fontWeight: notification.read ? '500' : '700',
              },
            ]}
          >
            {notification.title}
          </Text>
          <Text style={[itemStyles.timestamp, { color: color(tokens.text.tertiary) }]}>
            {notification.timestamp}
          </Text>
        </View>
        <Text
          style={[
            itemStyles.message,
            {
              color: notification.read
                ? color(tokens.text.secondary)
                : color(tokens.text.primary),
            },
          ]}
          numberOfLines={2}
        >
          {notification.message}
        </Text>
        {notification.amount && (
          <Text
            style={[itemStyles.amount, { color: color(config.color) }]}
          >
            {notification.type === 'payment_received' ? '+' : '-'}
            {notification.amount} {notification.asset}
          </Text>
        )}
      </View>
    </TouchableOpacity>
  );
}

const itemStyles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    padding: 16,
    borderRadius: 16,
    marginBottom: 8,
  },
  unreadDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginRight: 12,
    marginTop: 6,
  },
  iconContainer: {
    width: 44,
    height: 44,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
  },
  icon: {
    fontSize: 20,
  },
  content: {
    flex: 1,
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4,
  },
  title: {
    fontSize: 15,
    flex: 1,
    marginRight: 8,
  },
  timestamp: {
    fontSize: 12,
  },
  message: {
    fontSize: 14,
    lineHeight: 20,
    marginBottom: 4,
  },
  amount: {
    fontSize: 14,
    fontWeight: '700',
  },
});

function themedStyles({ color, isDark, tokens }: {
  color: (t: any) => string;
  isDark: boolean;
  tokens: typeof themeTokens;
}) {
  return StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: color(tokens.surface),
    },
    header: {
      flexDirection: 'row',
      alignItems: 'center',
      paddingHorizontal: 20,
      paddingTop: 16,
      paddingBottom: 12,
    },
    headerTitle: {
      fontSize: 28,
      fontWeight: '800',
      color: color(tokens.text.primary),
    },
    badge: {
      marginLeft: 12,
      minWidth: 24,
      height: 24,
      borderRadius: 12,
      backgroundColor: color(tokens.action.primary),
      alignItems: 'center',
      justifyContent: 'center',
      paddingHorizontal: 6,
    },
    badgeText: {
      color: color(tokens.text.inverse),
      fontSize: 13,
      fontWeight: '700',
    },
    listContent: {
      padding: 16,
      paddingTop: 8,
    },
    emptyState: {
      alignItems: 'center',
      justifyContent: 'center',
      paddingVertical: 80,
    },
    emptyIcon: {
      fontSize: 48,
      marginBottom: 16,
    },
    emptyTitle: {
      fontSize: 18,
      fontWeight: '700',
      color: color(tokens.text.primary),
      marginBottom: 8,
    },
    emptyDesc: {
      fontSize: 14,
      color: color(tokens.text.secondary),
      textAlign: 'center',
      maxWidth: 260,
      lineHeight: 20,
    },
  });
}