import { useLocalSearchParams, useRouter } from "expo-router";
import React from "react";
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { useTranslation } from 'react-i18next';

import { useEscrowDetail } from "../../hooks/useEscrowDetail";
import { useWallet } from "../../hooks/useWallet";
import {
  formatEscrowAmount,
  getEscrowStatus,
  type EscrowDetail,
  type EscrowStatus,
  type EscrowTimestamp,
} from "../../services/escrow";
import { useTheme } from "../../src/theme/ThemeContext";
import type { ThemeTokens } from "../../src/theme/tokens";

export default function EscrowDetailScreen() {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const router = useRouter();
  const params = useLocalSearchParams<{ id?: string | string[] }>();
  const id = Array.isArray(params.id) ? params.id[0] : params.id;
  const { state, refresh } = useEscrowDetail(id);
  const { wallet } = useWallet();

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <View style={[styles.navBar, { borderBottomColor: theme.border }]}>
        <Pressable
          onPress={() => router.back()}
          style={styles.navAction}
          accessibilityRole="button"
          accessibilityLabel="Go back"
        >
          <Text style={[styles.navActionText, { color: theme.link }]}>← Back</Text>
        </Pressable>
        <Text style={[styles.navTitle, { color: theme.textPrimary }]}>Escrow Detail</Text>
        <Pressable
          onPress={() => void refresh()}
          style={[styles.navAction, styles.refreshAction]}
          accessibilityRole="button"
          accessibilityLabel="Refresh escrow details"
        >
          <Text style={[styles.navActionText, { color: theme.link }]}>Refresh</Text>
        </Pressable>
      </View>

      {state.status === "loading" && (
        <View style={styles.center}>
          <ActivityIndicator size="large" color={theme.primary} />
          <Text style={[styles.stateText, { color: theme.textSecondary }]}>
            Loading escrow…
          </Text>
        </View>
      )}

      {state.status === "error" && (
        <View style={styles.center}>
          <Text style={[styles.errorText, { color: theme.status.error }]}>
            {state.notFound
              ? "This escrow could not be found or has expired."
              : state.error}
          </Text>
          {!state.notFound ? (
            <Pressable
              style={[styles.retryButton, { backgroundColor: theme.buttonPrimaryBg }]}
              onPress={() => void refresh()}
              accessibilityRole="button"
            >
              <Text style={[styles.retryText, { color: theme.buttonPrimaryText }]}>Retry</Text>
            </Pressable>
          ) : null}
        </View>
      )}

      {state.status === "success" ? (
        <ScrollView contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
          <EscrowContent
            detail={state.detail}
            viewerPublicKey={wallet.publicKey}
            theme={theme}
          />
        </ScrollView>
      ) : null}
    </SafeAreaView>
  );
}

function EscrowContent({
  detail,
  viewerPublicKey,
  theme,
}: {
  detail: EscrowDetail;
  viewerPublicKey?: string;
  theme: ThemeTokens;
}) {
  const status = getEscrowStatus(detail);
  const statusColor = getStatusColor(status, theme);
  const depositor = detail.depositor || "Not disclosed";
  const beneficiary = detail.beneficiary || "Not disclosed";
  const counterparty = getCounterparty(detail, viewerPublicKey);
  const amount = formatEscrowAmount(detail.amount);
  const assetCode = detail.assetCode?.trim() || "Unknown asset";
  const timestampRows = getTimestampRows(detail, status);

  return (
    <>
      <View style={[styles.card, styles.summaryCard, { backgroundColor: theme.surface, borderColor: theme.border }]}>
        <View style={styles.cardTop}>
          <Text style={[styles.sectionEyebrow, { color: theme.textMuted }]}>ESCROW</Text>
          <View style={[styles.statusBadge, { borderColor: statusColor, backgroundColor: theme.surface }]}>
            <Text style={[styles.statusText, { color: statusColor }]}>{statusLabel(status)}</Text>
          </View>
        </View>

        <View style={styles.amountBlock}>
          <Text style={[styles.amount, { color: theme.textPrimary }]}>{amount}</Text>
          <Text style={[styles.assetCode, { color: theme.textSecondary }]}>{assetCode}</Text>
        </View>

        <DetailRow label="Escrow ID" value={formatIdentifier(detail.id)} theme={theme} />
        <DetailRow
          label={counterparty ? "Counterparty" : "Escrow parties"}
          value={
            counterparty
              ? formatAddress(counterparty)
              : `Depositor ${formatAddress(depositor)} · Beneficiary ${formatAddress(beneficiary)}`
          }
          theme={theme}
        />
      </View>

      <View style={[styles.card, { backgroundColor: theme.surface, borderColor: theme.border }]}>
        <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>Participants</Text>
        <DetailRow label="Depositor" value={formatAddress(depositor)} theme={theme} />
        <DetailRow label="Beneficiary" value={formatAddress(beneficiary)} theme={theme} />
      </View>

      <View style={[styles.card, { backgroundColor: theme.surface, borderColor: theme.border }]}>
        <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>{t("escrow.timing")}</Text>
        {timestampRows.length > 0 ? (
          timestampRows.map((row) => (
            <DetailRow key={row.label} label={row.label} value={row.value} theme={theme} />
          ))
        ) : (
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>{t("escrow.timing")}</Text>
        )}
      </View>

      <View style={[styles.card, { backgroundColor: theme.surface, borderColor: theme.border }]}>
        <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>{t("escrow.actions")}</Text>
        <Text style={[styles.bodyText, { color: theme.textSecondary }]}>
          {actionGuidance(status)}
        </Text>
        <Text style={[styles.actionNote, { color: theme.textMuted }]}>
         {t("escrow.actionNote")}
        </Text>
      </View>
    </>
  );
}

function DetailRow({
  label,
  value,
  theme,
}: {
  label: string;
  value: string;
  theme: ThemeTokens;
}) {
  return (
    <View style={styles.detailRow}>
      <Text style={[styles.rowLabel, { color: theme.textMuted }]}>{label}</Text>
      <Text selectable style={[styles.rowValue, { color: theme.textSecondary }]}>
        {value}
      </Text>
    </View>
  );
}

function getCounterparty(detail: EscrowDetail, viewerPublicKey?: string): string | null {
  if (!viewerPublicKey) return null;

  const viewer = viewerPublicKey.toLowerCase();
  if (detail.depositor && viewer === detail.depositor.toLowerCase()) {
    return detail.beneficiary || null;
  }
  if (detail.beneficiary && viewer === detail.beneficiary.toLowerCase()) {
    return detail.depositor || null;
  }
  return null;
}

function getTimestampRows(detail: EscrowDetail, status: EscrowStatus): { label: string; value: string }[] {
  const rows: { label: string; value: string }[] = [];
  const createdAt = formatTimestamp(detail.createdAt ?? detail.created_at);
  const updatedAt = formatTimestamp(detail.updatedAt ?? detail.updated_at);
  const expiresAt = detail.expiresAt ?? detail.expires_at;
  const releasedAt = formatTimestamp(detail.releasedAt ?? detail.released_at);
  const refundedAt = formatTimestamp(detail.refundedAt ?? detail.refunded_at);

  if (createdAt) rows.push({ label: "Created", value: createdAt });
  if (updatedAt) rows.push({ label: "Updated", value: updatedAt });

  let expiryValue: string | null = null;
  if (expiresAt !== undefined && expiresAt !== null && expiresAt !== "") {
    const expiryNumber = typeof expiresAt === "number" ? expiresAt : Number(expiresAt);
    expiryValue = expiryNumber === 0 ? "No expiry" : formatTimestamp(expiresAt);
  }
  if (expiryValue) {
    rows.push({ label: "Expires", value: expiryValue });
  } else if (detail.expiryLedger !== undefined && detail.expiryLedger !== null) {
    const expiryLedger = Number(detail.expiryLedger);
    rows.push({
      label: "Expires at ledger",
      value: Number.isFinite(expiryLedger) && expiryLedger > 0 ? `#${Math.trunc(expiryLedger)}` : "No expiry",
    });
  }

  if (status === "released" && releasedAt) rows.push({ label: "Released", value: releasedAt });
  if ((status === "refunded" || status === "cancelled") && refundedAt) {
    rows.push({ label: "Refunded", value: refundedAt });
  }
  return rows;
}

function formatTimestamp(value: EscrowTimestamp | undefined): string | null {
  if (value === undefined || value === null || value === "") return null;

  let date: Date;
  if (typeof value === "number" || /^\d+(?:\.\d+)?$/.test(value)) {
    const numericValue = Number(value);
    if (!Number.isFinite(numericValue) || numericValue === 0) return null;
    date = new Date(Math.abs(numericValue) < 1_000_000_000_000 ? numericValue * 1000 : numericValue);
  } else {
    date = new Date(value);
  }

  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function formatAddress(value: string): string {
  if (!value || value === "Not disclosed") return value;
  if (value.length <= 20) return value;
  return `${value.slice(0, 8)}…${value.slice(-8)}`;
}

function formatIdentifier(value: string): string {
  if (!value) return "Unknown";
  if (value.length <= 28) return value;
  return `${value.slice(0, 12)}…${value.slice(-10)}`;
}

function statusLabel(status: EscrowStatus): string {
  const labels: Record<EscrowStatus, string> = {
    open: "Open",
    disputed: "Disputed",
    released: "Released",
    refunded: "Refunded",
    cancelled: "Cancelled",
    expired: "Expired",
    unknown: "Unknown",
  };
  return labels[status];
}

function getStatusColor(status: EscrowStatus, theme: ThemeTokens): string {
  switch (status) {
    case "released":
      return theme.status.success;
    case "open":
      return theme.status.info;
    case "disputed":
    case "expired":
      return theme.status.warning;
    case "refunded":
    case "cancelled":
      return theme.textMuted;
    case "unknown":
      return theme.textSecondary;
  }
}

function actionGuidance(status: EscrowStatus): string {
  switch (status) {
    case "open":
      return "Possible next steps are release by the beneficiary or opening a dispute when an arbiter is configured; both require on-chain authorization.";
    case "disputed":
      return "The funds are locked. The next step is resolution by the assigned arbiter or arbiters.";
    case "expired":
      return "The owner may be able to refund this escrow if the contract's expiry rules allow it.";
    case "released":
      return "The escrow has been released. No further action is available.";
    case "refunded":
    case "cancelled":
      return "The escrow has been refunded or cancelled. No further action is available.";
    case "unknown":
      return "The backend returned an escrow state this version of the app does not recognize. Refresh the details before taking action.";
  }
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  navBar: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: 1,
  },
  navAction: {
    width: 68,
    paddingVertical: 4,
  },
  refreshAction: {
    alignItems: "flex-end",
  },
  navActionText: {
    fontSize: 14,
    fontWeight: "600",
  },
  navTitle: {
    flex: 1,
    fontSize: 17,
    fontWeight: "700",
    textAlign: "center",
  },
  center: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    gap: 14,
    paddingHorizontal: 32,
  },
  stateText: {
    fontSize: 15,
    textAlign: "center",
  },
  errorText: {
    fontSize: 15,
    textAlign: "center",
  },
  retryButton: {
    paddingVertical: 12,
    paddingHorizontal: 28,
    borderRadius: 12,
  },
  retryText: {
    fontSize: 15,
    fontWeight: "700",
  },
  content: {
    padding: 16,
    gap: 14,
    paddingBottom: 32,
  },
  card: {
    borderRadius: 16,
    borderWidth: 1,
    padding: 16,
    gap: 14,
  },
  summaryCard: {
    gap: 16,
  },
  cardTop: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  sectionEyebrow: {
    fontSize: 12,
    fontWeight: "700",
    letterSpacing: 1,
  },
  statusBadge: {
    borderWidth: 1,
    borderRadius: 10,
    paddingVertical: 4,
    paddingHorizontal: 10,
  },
  statusText: {
    fontSize: 12,
    fontWeight: "700",
  },
  amountBlock: {
    gap: 4,
    paddingVertical: 4,
  },
  amount: {
    fontSize: 34,
    fontWeight: "800",
  },
  assetCode: {
    fontSize: 16,
    fontWeight: "600",
  },
  sectionTitle: {
    fontSize: 17,
    fontWeight: "700",
  },
  detailRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: 12,
  },
  rowLabel: {
    flex: 1,
    fontSize: 13,
    fontWeight: "600",
  },
  rowValue: {
    flex: 2,
    fontSize: 14,
    fontWeight: "600",
    textAlign: "right",
  },
  bodyText: {
    fontSize: 14,
    lineHeight: 21,
  },
  actionNote: {
    fontSize: 12,
    lineHeight: 18,
  },
});
