import { useRouter } from "expo-router";
import React, { useCallback, useEffect, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  Pressable,
  ActivityIndicator,
  Alert,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { Ionicons } from "@expo/vector-icons";

import { useWalletContext } from "../hooks/useWalletContext";
import { useEnvironment } from "../contexts/EnvironmentContext";
import { useTheme } from "../src/theme/ThemeContext";
import {
  fetchAnalytics,
  exportAnalyticsReport,
  clearAnalyticsCache,
  type DateRange,
  type AnalyticsData,
} from "../src/services/analyticsApi";
import { ErrorState } from "../components/resilience/error-state";
import { EmptyState } from "../components/resilience/empty-state";

const RANGES: { label: string; value: DateRange }[] = [
  { label: "24h", value: "24h" },
  { label: "7d", value: "7d" },
  { label: "30d", value: "30d" },
  { label: "All Time", value: "all" },
];

const REPORT_TYPES = ["accounting", "tax"] as const;
const EXPORT_FORMATS = ["csv", "pdf"] as const;

// ─── Helper Components ────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  change,
}: {
  label: string;
  value: string;
  change?: number;
}) {
  const { theme } = useTheme();
  const positive = (change ?? 0) >= 0;

  return (
    <View
      style={[
        styles.statCard,
        { backgroundColor: theme.surface, borderColor: theme.border },
      ]}
    >
      <Text style={[styles.statLabel, { color: theme.textMuted }]}>{label}</Text>
      <Text style={[styles.statValue, { color: theme.textPrimary }]}>
        {value}
      </Text>
      {change !== undefined && (
        <Text
          style={[
            styles.statChange,
            positive
              ? { color: theme.status.success }
              : { color: theme.status.error },
          ]}
        >
          {positive ? "+" : ""}
          {change}%
        </Text>
      )}
    </View>
  );
}

function AssetDistributionItem({
  name,
  value,
  color,
}: {
  name: string;
  value: number;
  color: string;
}) {
  const { theme } = useTheme();
  return (
    <View style={styles.assetItem}>
      <View
        style={[
          styles.assetColorDot,
          { backgroundColor: color },
        ]}
      />
      <Text style={[styles.assetName, { color: theme.textPrimary }]}>
        {name}
      </Text>
      <Text style={[styles.assetValue, { color: theme.textSecondary }]}>
        {value}%
      </Text>
    </View>
  );
}

function DateRangeFilter({
  active,
  onChange,
}: {
  active: DateRange;
  onChange: (range: DateRange) => void;
}) {
  const { theme } = useTheme();
  return (
    <View
      style={[
        styles.rangeFilter,
        { backgroundColor: theme.surfaceElevated, borderColor: theme.border },
      ]}
    >
      {RANGES.map((r) => (
        <Pressable
          key={r.value}
          onPress={() => onChange(r.value)}
          style={[
            styles.rangeChip,
            active === r.value
              ? { backgroundColor: theme.buttonPrimaryBg }
              : { backgroundColor: "transparent" },
          ]}
        >
          <Text
            style={[
              styles.rangeChipText,
              active === r.value
                ? { color: theme.buttonPrimaryText }
                : { color: theme.textSecondary },
            ]}
          >
            {r.label}
          </Text>
        </Pressable>
      ))}
    </View>
  );
}

// ─── Main Screen ───────────────────────────────────────────────────────────────

export default function AnalyticsScreen() {
  const router = useRouter();
  const { theme } = useTheme();
  const { wallet } = useWalletContext();
  const { currentId: environmentId } = useEnvironment();

  const [range, setRange] = useState<DateRange>("30d");
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reportType, setReportType] = useState<"accounting" | "tax">("accounting");
  const [exporting, setExporting] = useState<"csv" | "pdf" | null>(null);

  const publicKey = wallet.publicKey;

  const loadAnalytics = useCallback(async (r: DateRange) => {
    if (!publicKey) {
      setError("No wallet connected");
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const result = await fetchAnalytics(publicKey, r, environmentId);
      setData(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load analytics";
      setError(message);
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [publicKey, environmentId]);

  useEffect(() => {
    loadAnalytics(range);
  }, [range, loadAnalytics]);

  const handleRefresh = useCallback(() => {
    clearAnalyticsCache();
    loadAnalytics(range);
  }, [range, loadAnalytics]);

  const handleExport = useCallback(async (format: "csv" | "pdf") => {
    if (!publicKey) {
      Alert.alert("Error", "No wallet connected");
      return;
    }

    setExporting(format);
    try {
      await exportAnalyticsReport(publicKey, range, format, reportType, environmentId);
      Alert.alert("Success", `${format.toUpperCase()} report exported successfully`);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Export failed";
      Alert.alert("Export Error", message);
    } finally {
      setExporting(null);
    }
  }, [publicKey, range, reportType, environmentId]);

  const { summary, volume, txCount, assetDist } = data ?? {
    summary: null,
    volume: [],
    txCount: [],
    assetDist: [],
  };

  const formatCurrency = (n: number) =>
    n >= 1000 ? `$${(n / 1000).toFixed(1)}k` : `$${n.toFixed(2)}`;

  const formatNumber = (n: number) => n.toLocaleString();

  // ─── Loading State ─────────────────────────────────────────────────────────
  if (loading) {
    return (
      <SafeAreaView
        style={[styles.container, { backgroundColor: theme.surface }]}
        edges={["top", "bottom"]}
      >
        <View
          style={[
            styles.header,
            { backgroundColor: theme.headerBg, borderBottomColor: theme.border },
          ]}
        >
          <Pressable
            onPress={() => router.back()}
            style={styles.backBtn}
            hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
          >
            <Text style={[styles.backChevron, { color: theme.textPrimary }]}>
              ‹
            </Text>
          </Pressable>
          <Text style={[styles.headerTitle, { color: theme.textPrimary }]}>
            Analytics
          </Text>
          <View style={styles.backBtn} />
        </View>
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color={theme.textMuted} />
          <Text style={[styles.loadingText, { color: theme.textSecondary }]}>
            Loading analytics...
          </Text>
        </View>
      </SafeAreaView>
    );
  }

  // ─── Error State ───────────────────────────────────────────────────────────
  if (error) {
    return (
      <SafeAreaView
        style={[styles.container, { backgroundColor: theme.surface }]}
        edges={["top", "bottom"]}
      >
        <View
          style={[
            styles.header,
            { backgroundColor: theme.headerBg, borderBottomColor: theme.border },
          ]}
        >
          <Pressable
            onPress={() => router.back()}
            style={styles.backBtn}
            hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
          >
            <Text style={[styles.backChevron, { color: theme.textPrimary }]}>
              ‹
            </Text>
          </Pressable>
          <Text style={[styles.headerTitle, { color: theme.textPrimary }]}>
            Analytics
          </Text>
          <View style={styles.backBtn} />
        </View>
        <ErrorState message={error} onRetry={handleRefresh} />
      </SafeAreaView>
    );
  }

  // ─── Empty State ────────────────────────────────────────────────────────────
  if (!publicKey) {
    return (
      <SafeAreaView
        style={[styles.container, { backgroundColor: theme.surface }]}
        edges={["top", "bottom"]}
      >
        <View
          style={[
            styles.header,
            { backgroundColor: theme.headerBg, borderBottomColor: theme.border },
          ]}
        >
          <Pressable
            onPress={() => router.back()}
            style={styles.backBtn}
            hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
          >
            <Text style={[styles.backChevron, { color: theme.textPrimary }]}>
              ‹
            </Text>
          </Pressable>
          <Text style={[styles.headerTitle, { color: theme.textPrimary }]}>
            Analytics
          </Text>
          <View style={styles.backBtn} />
        </View>
        <EmptyState
          title="No wallet connected"
          message="Connect your wallet to view analytics"
          icon="wallet-outline"
        />
      </SafeAreaView>
    );
  }

  // ─── Main Content ──────────────────────────────────────────────────────────
  return (
    <SafeAreaView
      style={[styles.container, { backgroundColor: theme.surface }]}
      edges={["top", "bottom"]}
    >
      {/* Header */}
      <View
        style={[
          styles.header,
          { backgroundColor: theme.headerBg, borderBottomColor: theme.border },
        ]}
      >
        <Pressable
          onPress={() => router.back()}
          style={styles.backBtn}
          hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
        >
          <Text style={[styles.backChevron, { color: theme.textPrimary }]}>
            ‹
          </Text>
        </Pressable>
        <Text style={[styles.headerTitle, { color: theme.textPrimary }]}>
          Analytics
        </Text>
        <View style={styles.backBtn} />
      </View>

      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.scrollContent}
        showsVerticalScrollIndicator={false}
      >
        {/* Date Range Filter */}
        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
            Time Range
          </Text>
          <DateRangeFilter active={range} onChange={setRange} />
        </View>

        {/* Summary Stats */}
        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
            Summary
          </Text>
          <View style={styles.statsGrid}>
            <StatCard
              label="Total Volume"
              value={summary ? formatCurrency(summary.totalVolume) : "$0"}
              change={summary?.changeVolumePercent}
            />
            <StatCard
              label="Transactions"
              value={summary ? formatNumber(summary.totalTx) : "0"}
            />
            <StatCard
              label="Avg Tx Size"
              value={summary ? formatCurrency(summary.avgTxSize) : "$0"}
            />
            <StatCard
              label="Success Rate"
              value={summary ? `${summary.conversionRate.toFixed(1)}%` : "100%"}
            />
          </View>
        </View>

        {/* Asset Distribution */}
        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
            Asset Distribution
          </Text>
          {assetDist.length > 0 ? (
            <View
              style={[
                styles.assetList,
                { backgroundColor: theme.surface, borderColor: theme.border },
              ]}
            >
              {assetDist.map((asset, index) => (
                <AssetDistributionItem
                  key={`${asset.name}-${index}`}
                  name={asset.name}
                  value={asset.value}
                  color={asset.color}
                />
              ))}
            </View>
          ) : (
            <Text style={[styles.emptyText, { color: theme.textSecondary }]}>
              No asset data available
            </Text>
          )}
        </View>

        {/* Transaction Volume */}
        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
            Transaction Volume
          </Text>
          {volume.length > 0 ? (
            <View
              style={[
                styles.dataList,
                { backgroundColor: theme.surface, borderColor: theme.border },
              ]}
            >
              {volume.slice(0, 10).map((item, index) => (
                <View
                  key={index}
                  style={[styles.dataItem, { borderBottomColor: theme.border }]}
                >
                  <Text style={[styles.dataDate, { color: theme.textSecondary }]}>
                    {item.date}
                  </Text>
                  <Text style={[styles.dataValue, { color: theme.textPrimary }]}>
                    {formatCurrency(item.total)}
                  </Text>
                </View>
              ))}
            </View>
          ) : (
            <Text style={[styles.emptyText, { color: theme.textSecondary }]}>
              No volume data available
            </Text>
          )}
        </View>

        {/* Transaction Count */}
        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
            Transaction Count
          </Text>
          {txCount.length > 0 ? (
            <View
              style={[
                styles.dataList,
                { backgroundColor: theme.surface, borderColor: theme.border },
              ]}
            >
              {txCount.slice(0, 10).map((item, index) => (
                <View
                  key={index}
                  style={[styles.dataItem, { borderBottomColor: theme.border }]}
                >
                  <Text style={[styles.dataDate, { color: theme.textSecondary }]}>
                    {item.date}
                  </Text>
                  <Text style={[styles.dataValue, { color: theme.textPrimary }]}>
                    {formatNumber(item.count)}
                  </Text>
                </View>
              ))}
            </View>
          ) : (
            <Text style={[styles.emptyText, { color: theme.textSecondary }]}>
              No transaction count data available
            </Text>
          )}
        </View>

        {/* Export Section */}
        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
            Export Report
          </Text>
          <View style={styles.exportControls}>
            <View
              style={[
                styles.reportTypeSelector,
                { backgroundColor: theme.surfaceElevated, borderColor: theme.border },
              ]}
            >
              {REPORT_TYPES.map((type) => (
                <Pressable
                  key={type}
                  onPress={() => setReportType(type)}
                  style={[
                    styles.reportTypeChip,
                    reportType === type
                      ? { backgroundColor: theme.buttonPrimaryBg }
                      : { backgroundColor: "transparent" },
                  ]}
                >
                  <Text
                    style={[
                      styles.reportTypeText,
                      reportType === type
                        ? { color: theme.buttonPrimaryText }
                        : { color: theme.textSecondary },
                    ]}
                  >
                    {type.charAt(0).toUpperCase() + type.slice(1)}
                  </Text>
                </Pressable>
              ))}
            </View>
            <View style={styles.exportButtons}>
              <Pressable
                onPress={() => handleExport("csv")}
                disabled={exporting !== null}
                style={[
                  styles.exportButton,
                  {
                    backgroundColor: theme.buttonPrimaryBg,
                    opacity: exporting !== null ? 0.6 : 1,
                  },
                ]}
              >
                <Ionicons
                  name="document-text-outline"
                  size={18}
                  color={theme.buttonPrimaryText}
                />
                <Text
                  style={[
                    styles.exportButtonText,
                    { color: theme.buttonPrimaryText },
                  ]}
                >
                  {exporting === "csv" ? "Exporting..." : "Export CSV"}
                </Text>
              </Pressable>
              <Pressable
                onPress={() => handleExport("pdf")}
                disabled={exporting !== null}
                style={[
                  styles.exportButton,
                  {
                    backgroundColor: theme.surfaceElevated,
                    borderColor: theme.border,
                    borderWidth: 1,
                    opacity: exporting !== null ? 0.6 : 1,
                  },
                ]}
              >
                <Ionicons
                  name="document-outline"
                  size={18}
                  color={theme.textPrimary}
                />
                <Text
                  style={[
                    styles.exportButtonText,
                    { color: theme.textPrimary },
                  ]}
                >
                  {exporting === "pdf" ? "Exporting..." : "Export PDF"}
                </Text>
              </Pressable>
            </View>
          </View>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

// ─── Styles ─────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  header: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: StyleSheet.hairlineWidth,
  },
  headerTitle: {
    fontSize: 17,
    fontWeight: "600",
  },
  backBtn: {
    width: 36,
    alignItems: "center",
  },
  backChevron: {
    fontSize: 28,
    lineHeight: 32,
  },
  loadingContainer: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    gap: 12,
  },
  loadingText: {
    fontSize: 14,
  },
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    padding: 16,
    gap: 24,
  },
  section: {
    gap: 12,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: "700",
    textTransform: "uppercase",
    letterSpacing: 0.5,
  },
  rangeFilter: {
    flexDirection: "row",
    borderRadius: 12,
    borderWidth: 1,
    padding: 4,
  },
  rangeChip: {
    flex: 1,
    paddingVertical: 8,
    alignItems: "center",
    borderRadius: 8,
  },
  rangeChipText: {
    fontSize: 13,
    fontWeight: "600",
  },
  statsGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 12,
  },
  statCard: {
    flex: 1,
    minWidth: "45%",
    padding: 16,
    borderRadius: 12,
    borderWidth: 1,
    gap: 4,
  },
  statLabel: {
    fontSize: 11,
    fontWeight: "600",
    textTransform: "uppercase",
    letterSpacing: 0.5,
  },
  statValue: {
    fontSize: 20,
    fontWeight: "700",
  },
  statChange: {
    fontSize: 12,
    fontWeight: "600",
  },
  assetList: {
    borderRadius: 12,
    borderWidth: 1,
    padding: 12,
    gap: 8,
  },
  assetItem: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
  },
  assetColorDot: {
    width: 12,
    height: 12,
    borderRadius: 6,
  },
  assetName: {
    flex: 1,
    fontSize: 14,
    fontWeight: "600",
  },
  assetValue: {
    fontSize: 14,
    fontWeight: "700",
  },
  dataList: {
    borderRadius: 12,
    borderWidth: 1,
    padding: 12,
  },
  dataItem: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 10,
    borderBottomWidth: StyleSheet.hairlineWidth,
  },
  dataDate: {
    fontSize: 13,
    fontWeight: "500",
  },
  dataValue: {
    fontSize: 14,
    fontWeight: "700",
  },
  emptyText: {
    fontSize: 14,
    fontStyle: "italic",
    textAlign: "center",
    paddingVertical: 20,
  },
  exportControls: {
    gap: 12,
  },
  reportTypeSelector: {
    flexDirection: "row",
    borderRadius: 12,
    borderWidth: 1,
    padding: 4,
  },
  reportTypeChip: {
    flex: 1,
    paddingVertical: 10,
    alignItems: "center",
    borderRadius: 8,
  },
  reportTypeText: {
    fontSize: 14,
    fontWeight: "600",
  },
  exportButtons: {
    flexDirection: "row",
    gap: 12,
  },
  exportButton: {
    flex: 1,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
    paddingVertical: 12,
    borderRadius: 12,
  },
  exportButtonText: {
    fontSize: 14,
    fontWeight: "700",
  },
});