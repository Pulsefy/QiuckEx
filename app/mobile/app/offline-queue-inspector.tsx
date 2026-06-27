import React, { useEffect, useState } from "react";
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
  Platform,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";

import { useTheme } from "../src/theme/ThemeContext";
import { useNetworkStatus } from "../hooks/use-network-status";
import {
  getOfflineQueue,
  enqueueAction,
  dequeueAction,
  clearOfflineQueue,
  retryQueuedAction,
  processOfflineQueue,
  type QueuedAction,
} from "../services/offline-queue";

export default function OfflineQueueInspectorScreen() {
  const { theme } = useTheme();
  const { isConnected } = useNetworkStatus();
  const router = useRouter();

  const [queue, setQueue] = useState<QueuedAction[]>([]);
  const [loading, setLoading] = useState(false);
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Load the queue data from storage
  const loadQueue = async () => {
    setLoading(true);
    try {
      const data = await getOfflineQueue();
      // Sort: newest first
      setQueue(data.sort((a, b) => b.timestamp - a.timestamp));
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadQueue();
  }, []);

  // Action helpers
  const handleAddMock = async (type: "mock-success" | "mock-failure" | "mock-payment") => {
    let payload = {};
    if (type === "mock-payment") {
      payload = {
        amount: "50.00",
        asset: "USDC",
        destination: "GA5ZTHP...",
        memo: "Lunch payment",
      };
    } else {
      payload = {
        testId: Math.random().toString(36).substring(7),
        value: "Mock test payload info",
      };
    }
    await enqueueAction(type, payload);
    await loadQueue();
  };

  const handleRetrySingle = async (id: string) => {
    setProcessingId(id);
    try {
      await retryQueuedAction(id);
      await loadQueue();
    } catch (e) {
      console.error(e);
    } finally {
      setProcessingId(null);
    }
  };

  const handleRetryAll = async () => {
    setLoading(true);
    try {
      await processOfflineQueue();
      await loadQueue();
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteSingle = async (id: string) => {
    await dequeueAction(id);
    if (expandedId === id) setExpandedId(null);
    await loadQueue();
  };

  const handleClearAll = async () => {
    await clearOfflineQueue();
    setExpandedId(null);
    await loadQueue();
  };

  // Stats computation
  const stats = queue.reduce(
    (acc, curr) => {
      acc.total++;
      if (curr.status === "pending") acc.pending++;
      else if (curr.status === "retrying") acc.retrying++;
      else if (curr.status === "failed") acc.failed++;
      else if (curr.status === "completed") acc.completed++;
      return acc;
    },
    { total: 0, pending: 0, retrying: 0, failed: 0, completed: 0 }
  );

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]} edges={["top", "bottom"]}>
      {/* Top Header */}
      <View style={[styles.header, { borderBottomColor: theme.border }]}>
        <View style={styles.headerLeft}>
          <Pressable onPress={() => router.back()} style={styles.backButton}>
            <Ionicons name="arrow-back" size={24} color={theme.textPrimary} />
          </Pressable>
          <Text style={[styles.headerTitle, { color: theme.textPrimary }]}>Offline Queue</Text>
        </View>
        <View style={styles.headerRight}>
          <View
            style={[
              styles.networkBadge,
              { backgroundColor: isConnected ? theme.status.success + "20" : theme.status.warning + "20" },
            ]}
          >
            <Ionicons
              name={isConnected ? "wifi" : "cloud-offline"}
              size={14}
              color={isConnected ? theme.status.success : theme.status.warning}
            />
            <Text
              style={[
                styles.networkText,
                { color: isConnected ? theme.status.success : theme.status.warning },
              ]}
            >
              {isConnected ? "Online" : "Offline"}
            </Text>
          </View>
        </View>
      </View>

      <ScrollView contentContainerStyle={styles.scrollContent} keyboardShouldPersistTaps="handled">
        {/* Stats Grid */}
        <View style={styles.statsContainer}>
          <StatCard label="Total" count={stats.total} color={theme.textPrimary} theme={theme} />
          <StatCard label="Pending" count={stats.pending} color={theme.status.warning} theme={theme} />
          <StatCard label="Failed" count={stats.failed} color={theme.status.error} theme={theme} />
          <StatCard label="Done" count={stats.completed} color={theme.status.success} theme={theme} />
        </View>

        {/* Global Controls */}
        <View style={[styles.sectionCard, { backgroundColor: theme.surface, borderColor: theme.border }]}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>Queue Actions</Text>
          <View style={styles.actionButtonsRow}>
            <Pressable
              style={[styles.actionBtn, { backgroundColor: theme.buttonPrimaryBg }]}
              onPress={handleRetryAll}
              disabled={loading || queue.length === 0}
            >
              <Ionicons name="refresh" size={16} color={theme.buttonPrimaryText} />
              <Text style={[styles.actionBtnText, { color: theme.buttonPrimaryText }]}>Retry Pending</Text>
            </Pressable>

            <Pressable
              style={[styles.actionBtn, { backgroundColor: theme.status.error + "15", borderColor: theme.status.error, borderWidth: 1 }]}
              onPress={handleClearAll}
              disabled={loading || queue.length === 0}
            >
              <Ionicons name="trash-outline" size={16} color={theme.status.error} />
              <Text style={[styles.actionBtnText, { color: theme.status.error }]}>Clear Queue</Text>
            </Pressable>
          </View>
        </View>

        {/* Simulation Sandbox */}
        <View style={[styles.sectionCard, { backgroundColor: theme.surface, borderColor: theme.border }]}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>Simulation Sandbox (QA)</Text>
          <Text style={[styles.sectionSubtitle, { color: theme.textSecondary }]}>
            Enqueue fake activities to test background sync, inspect payloads, and practice manual retry loops.
          </Text>
          <View style={styles.sandboxButtons}>
            <Pressable style={[styles.sandboxBtn, { backgroundColor: theme.buttonSecondaryBg }]} onPress={() => handleAddMock("mock-success")}>
              <Ionicons name="add-circle-outline" size={16} color={theme.textPrimary} />
              <Text style={[styles.sandboxBtnText, { color: theme.textPrimary }]}>Mock Success</Text>
            </Pressable>
            <Pressable style={[styles.sandboxBtn, { backgroundColor: theme.buttonSecondaryBg }]} onPress={() => handleAddMock("mock-failure")}>
              <Ionicons name="add-circle-outline" size={16} color={theme.textPrimary} />
              <Text style={[styles.sandboxBtnText, { color: theme.textPrimary }]}>Mock Failure</Text>
            </Pressable>
            <Pressable style={[styles.sandboxBtn, { backgroundColor: theme.buttonSecondaryBg }]} onPress={() => handleAddMock("mock-payment")}>
              <Ionicons name="add-circle-outline" size={16} color={theme.textPrimary} />
              <Text style={[styles.sandboxBtnText, { color: theme.textPrimary }]}>Mock Payment</Text>
            </Pressable>
          </View>
        </View>

        {/* Queue List Header */}
        <View style={styles.listHeader}>
          <Text style={[styles.listTitle, { color: theme.textPrimary }]}>Queue History</Text>
          <Pressable onPress={loadQueue} disabled={loading} style={styles.refreshIcon}>
            <Ionicons name="reload" size={18} color={theme.textSecondary} />
          </Pressable>
        </View>

        {loading && queue.length === 0 ? (
          <ActivityIndicator size="large" color={theme.primary} style={{ marginTop: 24 }} />
        ) : queue.length === 0 ? (
          <View style={[styles.emptyCard, { backgroundColor: theme.surface, borderColor: theme.border }]}>
            <Ionicons name="file-tray-outline" size={48} color={theme.textMuted} />
            <Text style={[styles.emptyText, { color: theme.textSecondary }]}>No queued actions found</Text>
          </View>
        ) : (
          <View style={styles.listContainer}>
            {queue.map((item) => {
              const isExpanded = expandedId === item.id;
              const isProcessing = processingId === item.id;
              const formattedTime = new Date(item.timestamp).toLocaleTimeString();

              // Status badge details
              let badgeBg = theme.status.warning + "15";
              let badgeColor = theme.status.warning;
              let statusIcon: React.ComponentProps<typeof Ionicons>["name"] = "time-outline";

              if (item.status === "completed") {
                badgeBg = theme.status.success + "15";
                badgeColor = theme.status.success;
                statusIcon = "checkmark-circle-outline";
              } else if (item.status === "failed") {
                badgeBg = theme.status.error + "15";
                badgeColor = theme.status.error;
                statusIcon = "close-circle-outline";
              } else if (item.status === "retrying") {
                badgeBg = theme.primary + "15";
                badgeColor = theme.primary;
                statusIcon = "refresh-outline";
              }

              return (
                <View
                  key={item.id}
                  style={[
                    styles.itemCard,
                    { backgroundColor: theme.surface, borderColor: theme.border },
                  ]}
                >
                  <View style={styles.itemHeader}>
                    <View style={styles.itemHeaderLeft}>
                      <View style={[styles.statusBadge, { backgroundColor: badgeBg }]}>
                        <Ionicons name={statusIcon} size={14} color={badgeColor} />
                        <Text style={[styles.statusText, { color: badgeColor }]}>
                          {item.status}
                        </Text>
                      </View>
                      <Text style={[styles.itemType, { color: theme.textPrimary }]}>
                        {item.type}
                      </Text>
                    </View>
                    <Text style={[styles.itemTime, { color: theme.textMuted }]}>
                      {formattedTime}
                    </Text>
                  </View>

                  <View style={styles.itemMeta}>
                    <Text style={[styles.metaText, { color: theme.textSecondary }]}>
                      ID: <Text style={styles.monospace}>{item.id}</Text>
                    </Text>
                    <Text style={[styles.metaText, { color: theme.textSecondary }]}>
                      Attempts: <Text style={{ fontWeight: "700" }}>{item.attempts}</Text>
                    </Text>
                  </View>

                  {item.failureReason ? (
                    <View style={[styles.errorBox, { backgroundColor: theme.status.errorBg, borderColor: theme.status.error }]}>
                      <Text style={[styles.errorText, { color: theme.status.error }]}>
                        Error: {item.failureReason}
                      </Text>
                    </View>
                  ) : null}

                  {/* Expanded JSON details */}
                  {isExpanded && (
                    <View style={[styles.detailsBox, { backgroundColor: theme.background, borderColor: theme.border }]}>
                      <Text style={[styles.detailsHeading, { color: theme.textPrimary }]}>Payload Details</Text>
                      <Text style={[styles.detailsJson, { color: theme.textSecondary }]}>
                        {JSON.stringify(item.payload, null, 2)}
                      </Text>
                    </View>
                  )}

                  {/* Item Actions */}
                  <View style={[styles.itemActions, { borderTopColor: theme.border }]}>
                    <Pressable
                      style={styles.itemActionBtn}
                      onPress={() => setExpandedId(isExpanded ? null : item.id)}
                    >
                      <Ionicons
                        name={isExpanded ? "eye-off-outline" : "eye-outline"}
                        size={16}
                        color={theme.textSecondary}
                      />
                      <Text style={[styles.itemActionBtnText, { color: theme.textSecondary }]}>
                        {isExpanded ? "Hide Payloads" : "Inspect"}
                      </Text>
                    </Pressable>

                    {(item.status === "pending" || item.status === "failed") && (
                      <Pressable
                        style={styles.itemActionBtn}
                        onPress={() => handleRetrySingle(item.id)}
                        disabled={isProcessing}
                      >
                        {isProcessing ? (
                          <ActivityIndicator size="small" color={theme.primary} />
                        ) : (
                          <>
                            <Ionicons name="refresh-outline" size={16} color={theme.primary} />
                            <Text style={[styles.itemActionBtnText, { color: theme.primary }]}>
                              Retry
                            </Text>
                          </>
                        )}
                      </Pressable>
                    )}

                    <Pressable
                      style={styles.itemActionBtn}
                      onPress={() => handleDeleteSingle(item.id)}
                    >
                      <Ionicons name="trash-outline" size={16} color={theme.status.error} />
                      <Text style={[styles.itemActionBtnText, { color: theme.status.error }]}>
                        Remove
                      </Text>
                    </Pressable>
                  </View>
                </View>
              );
            })}
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

function StatCard({
  label,
  count,
  color,
  theme,
}: {
  label: string;
  count: number;
  color: string;
  theme: any;
}) {
  return (
    <View style={[styles.statCard, { backgroundColor: theme.surface, borderColor: theme.border }]}>
      <Text style={[styles.statLabel, { color: theme.textSecondary }]}>{label}</Text>
      <Text style={[styles.statCount, { color }]}>{count}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  header: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    paddingHorizontal: 16,
    paddingVertical: 14,
    borderBottomWidth: 1,
  },
  headerLeft: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
  },
  backButton: {
    padding: 2,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: "700",
  },
  headerRight: {},
  networkBadge: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 8,
    gap: 4,
  },
  networkText: {
    fontSize: 12,
    fontWeight: "600",
  },
  scrollContent: {
    padding: 16,
    gap: 16,
    paddingBottom: 40,
  },
  statsContainer: {
    flexDirection: "row",
    gap: 8,
  },
  statCard: {
    flex: 1,
    padding: 10,
    borderRadius: 12,
    borderWidth: 1,
    alignItems: "center",
  },
  statLabel: {
    fontSize: 11,
    fontWeight: "500",
    marginBottom: 4,
  },
  statCount: {
    fontSize: 18,
    fontWeight: "700",
  },
  sectionCard: {
    borderRadius: 14,
    borderWidth: 1,
    padding: 16,
    gap: 12,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: "700",
  },
  sectionSubtitle: {
    fontSize: 12,
    lineHeight: 18,
  },
  actionButtonsRow: {
    flexDirection: "row",
    gap: 12,
  },
  actionBtn: {
    flex: 1,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 6,
    borderRadius: 10,
    paddingVertical: 10,
  },
  actionBtnText: {
    fontSize: 13,
    fontWeight: "600",
  },
  sandboxButtons: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
  },
  sandboxBtn: {
    flexDirection: "row",
    alignItems: "center",
    gap: 4,
    borderRadius: 10,
    paddingVertical: 8,
    paddingHorizontal: 12,
  },
  sandboxBtnText: {
    fontSize: 12,
    fontWeight: "600",
  },
  listHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginTop: 8,
  },
  listTitle: {
    fontSize: 18,
    fontWeight: "700",
  },
  refreshIcon: {
    padding: 4,
  },
  emptyCard: {
    borderRadius: 14,
    borderWidth: 1,
    padding: 32,
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
  },
  emptyText: {
    fontSize: 14,
  },
  listContainer: {
    gap: 12,
  },
  itemCard: {
    borderRadius: 14,
    borderWidth: 1,
    padding: 14,
    gap: 10,
  },
  itemHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  itemHeaderLeft: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  statusBadge: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 6,
    gap: 4,
  },
  statusText: {
    fontSize: 11,
    fontWeight: "700",
  },
  itemType: {
    fontSize: 14,
    fontWeight: "700",
  },
  itemTime: {
    fontSize: 12,
  },
  itemMeta: {
    flexDirection: "row",
    gap: 12,
  },
  metaText: {
    fontSize: 12,
  },
  monospace: {
    fontFamily: Platform.OS === "ios" ? "Courier New" : "monospace",
    fontSize: 11,
  },
  errorBox: {
    borderWidth: 1,
    borderRadius: 8,
    padding: 8,
  },
  errorText: {
    fontSize: 12,
    lineHeight: 16,
  },
  detailsBox: {
    borderWidth: 1,
    borderRadius: 8,
    padding: 10,
    gap: 6,
  },
  detailsHeading: {
    fontSize: 12,
    fontWeight: "700",
  },
  detailsJson: {
    fontFamily: Platform.OS === "ios" ? "Courier New" : "monospace",
    fontSize: 11,
    lineHeight: 15,
  },
  itemActions: {
    borderTopWidth: 1,
    paddingTop: 10,
    flexDirection: "row",
    justifyContent: "space-between",
  },
  itemActionBtn: {
    flexDirection: "row",
    alignItems: "center",
    gap: 4,
    padding: 4,
  },
  itemActionBtnText: {
    fontSize: 12,
    fontWeight: "600",
  },
});
