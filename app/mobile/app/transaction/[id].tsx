import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
    View,
    Text,
    StyleSheet,
    ScrollView,
    TouchableOpacity,
    Switch,
    Share,
    ActivityIndicator,
    Alert,
    Linking,
} from 'react-native';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as Haptics from 'expo-haptics';
import * as Clipboard from 'expo-clipboard';
import * as FileSystem from 'expo-file-system';
import * as Sharing from 'expo-sharing';
import { Ionicons } from '@expo/vector-icons';
import { useTheme } from '../../src/theme/ThemeContext';
import { StatusTimeline } from '../../components/transaction/StatusTimeline';
import { CopyableRow } from '../../components/transaction/CopyableRow';
import { findTransactionInCache } from '../../services/cache';
import type { TransactionItem } from '../../types/transaction';

const fileSystemCompat = FileSystem as typeof FileSystem & {
    cacheDirectory?: string | null;
};

type ReceiptVisibilityOptions = {
    showSender: boolean;
    showRecipient: boolean;
    showMemo: boolean;
    showHash: boolean;
};

const DEFAULT_RECEIPT_VISIBILITY: ReceiptVisibilityOptions = {
    showSender: false,
    showRecipient: true,
    showMemo: true,
    showHash: true,
};

interface DetailParams {
    id: string;
    amount?: string;
    asset?: string;
    memo?: string;
    timestamp?: string;
    txHash?: string;
    source?: string;
    destination?: string;
    status?: string;
}

function formatDate(iso: string | undefined, locale = 'en-US'): string {
    if (!iso) return 'Unknown';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return 'Invalid date';
    return d.toLocaleString(locale, {
        month: 'long',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    });
}

function formatShortDate(iso: string | undefined, locale = 'en-US'): string {
    if (!iso) return '';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '';
    return d.toLocaleString(locale, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

function formatAsset(asset: string | undefined): string {
    if (!asset) return 'XLM';
    const colonIdx = asset.indexOf(':');
    return colonIdx === -1 ? asset : asset.slice(0, colonIdx);
}

function shorten(str: string | undefined, head = 10, tail = 10): string {
    if (!str) return 'N/A';
    if (str.length <= head + tail + 3) return str;
    return `${str.slice(0, head)}...${str.slice(-tail)}`;
}

function buildTimelineSteps(
    timestamp: string | undefined,
    status: string,
): import('../../components/transaction/StatusTimeline').TimelineStep[] {
    const formattedTime = formatDate(timestamp);
    const shortTime = formatShortDate(timestamp);
    const isSuccess = status === 'Success';
    const isPending = status === 'Pending';

    return [
        {
            title: 'Transaction Initiated',
            subtitle: 'Submitted to the Stellar network',
            time: formattedTime,
            isCompleted: true,
        },
        {
            title: 'Validated on Network',
            subtitle: 'Confirmed by consensus',
            time: isSuccess || isPending ? formattedTime : undefined,
            isCompleted: isSuccess || isPending,
        },
        {
            title: isSuccess ? 'Completed' : isPending ? 'Processing' : 'Failed',
            subtitle: isSuccess
                ? 'Funds have been transferred'
                : isPending
                    ? 'Awaiting final confirmation'
                    : 'Transaction did not complete',
            time: isSuccess ? shortTime : isPending ? 'In progress...' : undefined,
            isCompleted: isSuccess,
            isActive: isPending,
        },
    ];
}

function buildShareMessage(transaction: TransactionItem): string {
    const asset = formatAsset(transaction.asset);
    const deepLink = buildReceiptLink(transaction);
    const lines = [
        'QuickEx Transaction Receipt',
        '───────────────────────────',
        `Amount: ${transaction.amount} ${asset}`,
        `Status: ${transaction.status}`,
        `Date: ${formatDate(transaction.timestamp)}`,
    ];
    if (transaction.source) lines.push(`From: ${transaction.source}`);
    if (transaction.destination) lines.push(`To: ${transaction.destination}`);
    if (transaction.memo) lines.push(`Memo: ${transaction.memo}`);
    lines.push(`Hash: ${transaction.txHash}`);
    lines.push(`View: ${deepLink}`);
    lines.push('───────────────────────────');
    lines.push('Powered by QuickEx');
    return lines.join('\n');
}

function buildReceiptLink(transaction: TransactionItem): string {
    return `https://quickex.to/transaction/${transaction.pagingToken}`;
}

function escapeXml(value: string): string {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

function buildReceiptSvg(
    transaction: TransactionItem,
    visibility: ReceiptVisibilityOptions,
): string {
    const accentColor =
        transaction.status === 'Success' ? '#34D399' : '#F59E0B';
    const surfaceColor = '#0B1220';
    const secondarySurfaceColor = '#121A2B';
    const link = buildReceiptLink(transaction);
    const rows = [
        `Amount|${transaction.amount} ${formatAsset(transaction.asset)}`,
        `Status|${transaction.status}`,
        `Date|${formatDate(transaction.timestamp)}`,
        visibility.showRecipient
            ? `Recipient|${transaction.destination || 'Hidden'}`
            : null,
        visibility.showSender ? `Sender|${transaction.source || 'Hidden'}` : null,
        visibility.showMemo ? `Memo|${transaction.memo || 'None'}` : null,
        visibility.showHash ? `Tx Hash|${transaction.txHash}` : null,
        `Receipt Link|${link}`,
    ].filter(Boolean) as string[];

    const rowMarkup = rows
        .map((entry, index) => {
            const [label, value] = entry.split('|');
            const y = 214 + index * 50;
            return `
        <text x="48" y="${y}" fill="#91A3BF" font-family="Arial" font-size="15" font-weight="700">${escapeXml(
                label,
            )}</text>
        <text x="48" y="${y + 22}" fill="#F8FAFC" font-family="Arial" font-size="18">${escapeXml(
                value,
            )}</text>
      `;
        })
        .join('');

    return `
<svg width="1200" height="720" viewBox="0 0 1200 720" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#172554" />
      <stop offset="60%" stop-color="${surfaceColor}" />
      <stop offset="100%" stop-color="#020617" />
    </linearGradient>
    <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="${accentColor}" />
      <stop offset="100%" stop-color="#60A5FA" />
    </linearGradient>
  </defs>
  <rect width="1200" height="720" rx="36" fill="url(#bg)" />
  <circle cx="1060" cy="120" r="180" fill="#1D4ED8" opacity="0.14" />
  <circle cx="120" cy="620" r="220" fill="#10B981" opacity="0.12" />
  <rect x="40" y="40" width="1120" height="640" rx="32" fill="${secondarySurfaceColor}" opacity="0.92" />
  <rect x="48" y="48" width="1104" height="10" rx="5" fill="url(#accent)" />
  <text x="48" y="112" fill="#93C5FD" font-family="Arial" font-size="24" font-weight="700">QuickEx Receipt v2</text>
  <text x="48" y="176" fill="#FFFFFF" font-family="Arial" font-size="72" font-weight="700">${escapeXml(
        transaction.amount,
    )} ${escapeXml(formatAsset(transaction.asset))}</text>
  <text x="48" y="620" fill="#93C5FD" font-family="Arial" font-size="20" font-weight="700">Shareable receipt link</text>
  <text x="48" y="652" fill="#E2E8F0" font-family="Arial" font-size="24">${escapeXml(
        link,
    )}</text>
  <rect x="860" y="88" width="240" height="88" rx="24" fill="#0F172A" opacity="0.85" />
  <text x="892" y="126" fill="#94A3B8" font-family="Arial" font-size="18" font-weight="700">Status</text>
  <text x="892" y="158" fill="${accentColor}" font-family="Arial" font-size="30" font-weight="700">${escapeXml(
        transaction.status,
    )}</text>
  ${rowMarkup}
</svg>
  `.trim();
}

export default function TransactionDetailScreen() {
    const { theme, isDark } = useTheme();
    const router = useRouter();
    const params = useLocalSearchParams<DetailParams>();

    const [hydrating, setHydrating] = useState(false);
    const [transaction, setTransaction] = useState<TransactionItem | null>(null);
    const [copyFeedback, setCopyFeedback] = useState<string | null>(null);
    const [receiptVisibility, setReceiptVisibility] =
        useState<ReceiptVisibilityOptions>(DEFAULT_RECEIPT_VISIBILITY);

    const hasFullParams = Boolean(
        params.amount && params.asset && params.txHash,
    );

    // Hydrate from cache when opened via deep link with incomplete params
    useEffect(() => {
        if (hasFullParams) return;
        if (!params.id) return;

        let cancelled = false;
        setHydrating(true);

        findTransactionInCache(params.id).then((cached) => {
            if (cancelled) return;
            if (cached) {
                setTransaction(cached);
            }
            setHydrating(false);
        });

        return () => {
            cancelled = true;
        };
    }, [hasFullParams, params.id]);

    // Build the effective transaction object
    const tx: TransactionItem = useMemo(() => {
        if (transaction) return transaction;
        return {
            amount: params.amount ?? '0',
            asset: params.asset ?? 'XLM',
            memo: params.memo,
            timestamp: params.timestamp ?? new Date().toISOString(),
            txHash: params.txHash ?? params.id,
            pagingToken: params.id,
            source: params.source ?? '',
            destination: params.destination ?? '',
            status: (params.status as 'Success' | 'Pending') ?? 'Success',
        };
    }, [transaction, params]);

    const assetLabel = formatAsset(tx.asset);
    const formattedAmount = useMemo(() => {
        const num = parseFloat(tx.amount || '0');
        return Number.isNaN(num) ? '0.00' : num.toFixed(2);
    }, [tx.amount]);

    const timelineSteps = useMemo(
        () => buildTimelineSteps(tx.timestamp, tx.status),
        [tx.timestamp, tx.status],
    );
    const receiptLink = useMemo(() => buildReceiptLink(tx), [tx]);

    const handleShare = useCallback(async () => {
        try {
            await Haptics.selectionAsync();
            const svg = buildReceiptSvg(tx, receiptVisibility);
            const cacheDirectory = fileSystemCompat.cacheDirectory ?? '';
            if (cacheDirectory) {
                const fileUri = `${cacheDirectory}quickex-receipt-${tx.pagingToken}.svg`;
                await FileSystem.writeAsStringAsync(fileUri, svg, {
                    encoding: 'utf8',
                });
                const canShareFile = await Sharing.isAvailableAsync();
                if (canShareFile) {
                    await Sharing.shareAsync(fileUri, {
                        mimeType: 'image/svg+xml',
                        dialogTitle: 'Share QuickEx receipt',
                        UTI: 'public.svg-image',
                    });
                    await Haptics.notificationAsync(
                        Haptics.NotificationFeedbackType.Success,
                    );
                    return;
                }
            }

            const message = buildShareMessage(tx);
            await Share.share({
                message,
                title: 'QuickEx Transaction Receipt',
            });
            await Haptics.notificationAsync(
                Haptics.NotificationFeedbackType.Success,
            );
        } catch (error) {
            // User dismissed or share failed silently
            console.debug('Share dismissed or failed', error);
        }
    }, [receiptVisibility, tx]);

    const handleCopyReceiptLink = useCallback(async () => {
        try {
            await Haptics.selectionAsync();
            await Clipboard.setStringAsync(receiptLink);
            setCopyFeedback('Receipt link copied');
            await Haptics.notificationAsync(
                Haptics.NotificationFeedbackType.Success,
            );
        } catch (error) {
            console.debug('Link copy failed', error);
        }
    }, [receiptLink]);

    const showCopyFeedback = useCallback(
        (label: string) => {
            setCopyFeedback(`${label} copied`);
            const timer = setTimeout(() => setCopyFeedback(null), 2000);
            return () => clearTimeout(timer);
        },
        [setCopyFeedback],
    );

    const statusColor =
        tx.status === 'Success'
            ? theme.status.success
            : tx.status === 'Pending'
                ? theme.status.warning
                : theme.status.error;

    const statusBg =
        tx.status === 'Success'
            ? theme.status.successBg
            : tx.status === 'Pending'
                ? theme.status.warningBg
                : theme.status.errorBg;

    return (
        <SafeAreaView
            style={[styles.container, { backgroundColor: theme.surface }]}
            edges={['top', 'bottom']}
        >
            {/* Header */}
            <View
                style={[
                    styles.header,
                    { borderBottomColor: theme.border },
                ]}
            >
                <TouchableOpacity
                    onPress={() => router.back()}
                    style={styles.iconButton}
                    hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
                >
                    <Ionicons
                        name="chevron-back"
                        size={24}
                        color={theme.textPrimary}
                    />
                </TouchableOpacity>
                <Text
                    style={[
                        styles.headerTitle,
                        { color: theme.textPrimary },
                    ]}
                >
                    Transaction Receipt
                </Text>
                <TouchableOpacity
                    onPress={handleShare}
                    style={styles.iconButton}
                    hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
                    accessibilityLabel="Share receipt"
                    accessibilityRole="button"
                >
                    <Ionicons
                        name="share-outline"
                        size={22}
                        color={theme.textPrimary}
                    />
                </TouchableOpacity>
            </View>

            {/* Copy feedback toast */}
            {copyFeedback && (
                <View
                    style={[
                        styles.toast,
                        {
                            backgroundColor: isDark
                                ? 'rgba(255,255,255,0.15)'
                                : 'rgba(0,0,0,0.75)',
                        },
                    ]}
                >
                    <Ionicons
                        name="checkmark-circle"
                        size={16}
                        color="#34D399"
                    />
                    <Text style={styles.toastText}>{copyFeedback}</Text>
                </View>
            )}

            <ScrollView
                showsVerticalScrollIndicator={false}
                contentContainerStyle={styles.scrollContent}
            >
                {hydrating && (
                    <View style={styles.hydrating}>
                        <ActivityIndicator color={theme.primary} />
                        <Text
                            style={[
                                styles.hydratingText,
                                { color: theme.textSecondary },
                            ]}
                        >
                            Loading transaction details...
                        </Text>
                    </View>
                )}

                {/* Hero Section */}
                <View style={styles.hero}>
                    <View
                        style={[
                            styles.statusBadge,
                            { backgroundColor: statusBg },
                        ]}
                    >
                        <View
                            style={[
                                styles.statusDot,
                                { backgroundColor: statusColor },
                            ]}
                        />
                        <Text
                            style={[
                                styles.statusText,
                                { color: statusColor },
                            ]}
                        >
                            {tx.status || 'Success'}
                        </Text>
                    </View>
                    <Text
                        style={[
                            styles.amount,
                            { color: theme.textPrimary },
                        ]}
                    >
                        {formattedAmount}
                    </Text>
                    <Text
                        style={[
                            styles.assetCode,
                            { color: theme.textSecondary },
                        ]}
                    >
                        {assetLabel}
                    </Text>
                    <Text
                        style={[
                            styles.timestamp,
                            { color: theme.textMuted },
                        ]}
                    >
                        {formatDate(tx.timestamp)}
                    </Text>
                </View>

                <View style={styles.section}>
                    <Text
                        style={[
                            styles.sectionTitle,
                            { color: theme.textPrimary },
                        ]}
                    >
                        Shareable Receipt
                    </Text>
                    <View
                        style={[
                            styles.card,
                            styles.receiptCard,
                            {
                                backgroundColor: theme.surfaceElevated,
                                borderColor: theme.border,
                            },
                        ]}
                    >
                        <View
                            style={[
                                styles.receiptPreview,
                                { backgroundColor: theme.primary },
                            ]}
                        >
                            <View style={styles.receiptGlow} />
                            <Text style={styles.receiptEyebrow}>QuickEx Receipt v2</Text>
                            <Text style={styles.receiptAmount}>
                                {formattedAmount} {assetLabel}
                            </Text>
                            <Text style={styles.receiptStatus}>
                                {tx.status} • {formatShortDate(tx.timestamp)}
                            </Text>
                            <View style={styles.receiptPreviewRows}>
                                <Text style={styles.receiptPreviewRow}>
                                    Recipient: {receiptVisibility.showRecipient ? shorten(tx.destination, 8, 8) : 'Hidden'}
                                </Text>
                                <Text style={styles.receiptPreviewRow}>
                                    Memo: {receiptVisibility.showMemo ? tx.memo || 'None' : 'Hidden'}
                                </Text>
                                <Text style={styles.receiptPreviewRow}>
                                    Tx Hash: {receiptVisibility.showHash ? shorten(tx.txHash, 8, 8) : 'Hidden'}
                                </Text>
                            </View>
                            <Text style={styles.receiptLinkPreview}>
                                {receiptLink}
                            </Text>
                        </View>

                        <View style={styles.receiptActionsRow}>
                            <TouchableOpacity
                                onPress={handleShare}
                                activeOpacity={0.8}
                                style={[
                                    styles.secondaryActionButton,
                                    { backgroundColor: theme.buttonPrimaryBg },
                                ]}
                            >
                                <Ionicons
                                    name="image-outline"
                                    size={18}
                                    color={theme.buttonPrimaryText}
                                />
                                <Text
                                    style={[
                                        styles.secondaryActionText,
                                        { color: theme.buttonPrimaryText },
                                    ]}
                                >
                                    Share image
                                </Text>
                            </TouchableOpacity>
                            <TouchableOpacity
                                onPress={handleCopyReceiptLink}
                                activeOpacity={0.8}
                                style={[
                                    styles.secondaryActionButton,
                                    {
                                        backgroundColor: theme.surface,
                                        borderColor: theme.border,
                                    },
                                ]}
                            >
                                <Ionicons
                                    name="link-outline"
                                    size={18}
                                    color={theme.textPrimary}
                                />
                                <Text
                                    style={[
                                        styles.secondaryActionText,
                                        { color: theme.textPrimary },
                                    ]}
                                >
                                    Copy link
                                </Text>
                            </TouchableOpacity>
                        </View>

                        <View style={styles.privacySection}>
                            <Text
                                style={[
                                    styles.privacyTitle,
                                    { color: theme.textPrimary },
                                ]}
                            >
                                Privacy controls
                            </Text>
                            {[
                                {
                                    key: 'showRecipient' as const,
                                    label: 'Show recipient',
                                    description: 'Include the payout destination on the shared receipt.',
                                },
                                {
                                    key: 'showSender' as const,
                                    label: 'Show sender',
                                    description: 'Reveal the sender address on the exported image.',
                                },
                                {
                                    key: 'showMemo' as const,
                                    label: 'Show memo',
                                    description: 'Include the payment memo in the shareable receipt.',
                                },
                                {
                                    key: 'showHash' as const,
                                    label: 'Show transaction hash',
                                    description: 'Attach the full transaction reference to the shared image.',
                                },
                            ].map((option) => (
                                <View
                                    key={option.key}
                                    style={[
                                        styles.privacyRow,
                                        { borderBottomColor: theme.border },
                                    ]}
                                >
                                    <View style={styles.privacyCopy}>
                                        <Text
                                            style={[
                                                styles.privacyLabel,
                                                { color: theme.textPrimary },
                                            ]}
                                        >
                                            {option.label}
                                        </Text>
                                        <Text
                                            style={[
                                                styles.privacyDescription,
                                                { color: theme.textSecondary },
                                            ]}
                                        >
                                            {option.description}
                                        </Text>
                                    </View>
                                    <Switch
                                        value={receiptVisibility[option.key]}
                                        onValueChange={(value) =>
                                            setReceiptVisibility((current) => ({
                                                ...current,
                                                [option.key]: value,
                                            }))
                                        }
                                        trackColor={{
                                            false: theme.border,
                                            true: theme.primary,
                                        }}
                                        thumbColor="#FFFFFF"
                                    />
                                </View>
                            ))}
                        </View>
                    </View>
                </View>

                {/* Timeline Section */}
                <View style={styles.section}>
                    <Text
                        style={[
                            styles.sectionTitle,
                            { color: theme.textPrimary },
                        ]}
                    >
                        Status Timeline
                    </Text>
                    <View
                        style={[
                            styles.card,
                            {
                                backgroundColor: theme.surfaceElevated,
                                borderColor: theme.border,
                            },
                        ]}
                    >
                        <View style={styles.timelinePadding}>
                            <StatusTimeline
                                steps={timelineSteps}
                                theme={theme}
                            />
                        </View>
                    </View>
                </View>

                {/* Details Section */}
                <View style={styles.section}>
                    <Text
                        style={[
                            styles.sectionTitle,
                            { color: theme.textPrimary },
                        ]}
                    >
                        Details
                    </Text>
                    <View
                        style={[
                            styles.card,
                            {
                                backgroundColor: theme.surfaceElevated,
                                borderColor: theme.border,
                            },
                        ]}
                    >
                        <CopyableRow
                            label="Transaction ID"
                            value={shorten(tx.pagingToken, 14, 14)}
                            rawValue={tx.pagingToken}
                            theme={theme}
                            onCopy={() => showCopyFeedback('Transaction ID')}
                        />
                        <CopyableRow
                            label="Transaction Hash"
                            value={shorten(tx.txHash, 10, 10)}
                            rawValue={tx.txHash}
                            theme={theme}
                            onCopy={() =>
                                showCopyFeedback('Transaction Hash')
                            }
                        />
                        <CopyableRow
                            label="Sender"
                            value={shorten(tx.source, 10, 10)}
                            rawValue={tx.source}
                            theme={theme}
                            onCopy={() => showCopyFeedback('Sender Address')}
                        />
                        <CopyableRow
                            label="Recipient"
                            value={shorten(tx.destination, 10, 10)}
                            rawValue={tx.destination}
                            theme={theme}
                            onCopy={() =>
                                showCopyFeedback('Recipient Address')
                            }
                        />
                        <CopyableRow
                            label="Memo"
                            value={tx.memo || 'None'}
                            rawValue={tx.memo}
                            theme={theme}
                            isLast
                            onCopy={() => showCopyFeedback('Memo')}
                        />
                    </View>
                </View>

                {/* Share CTA */}
                <TouchableOpacity
                    onPress={handleShare}
                    activeOpacity={0.75}
                    style={[
                        styles.shareButton,
                        {
                            backgroundColor: theme.buttonPrimaryBg,
                        },
                    ]}
                    accessibilityLabel="Share receipt"
                    accessibilityRole="button"
                >
                    <Ionicons
                        name="share-social"
                        size={18}
                        color={theme.buttonPrimaryText}
                    />
                    <Text
                        style={[
                            styles.shareButtonText,
                            { color: theme.buttonPrimaryText },
                        ]}
                    >
                        Share Receipt
                    </Text>
                </TouchableOpacity>

                {/* Explorer Link */}
                <TouchableOpacity
                    onPress={() => {
                        Alert.alert(
                            'Open Explorer',
                            'View this transaction on Stellar Expert?',
                            [
                                { text: 'Cancel', style: 'cancel' },
                                {
                                    text: 'Open',
                                    onPress: () => {
                                        const url = `https://stellar.expert/explorer/public/tx/${tx.txHash}`;
                                        Linking.openURL(url).catch(() => {
                                            Alert.alert('Unable to open link');
                                        });
                                    },
                                },
                            ],
                        );
                    }}
                    style={styles.explorerLink}
                    activeOpacity={0.6}
                >
                    <Text
                        style={[
                            styles.explorerText,
                            { color: theme.link },
                        ]}
                    >
                        View on Stellar Expert
                    </Text>
                    <Ionicons
                        name="open-outline"
                        size={14}
                        color={theme.link}
                    />
                </TouchableOpacity>

                <View style={{ height: 40 }} />
            </ScrollView>
        </SafeAreaView>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
    },
    header: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingHorizontal: 16,
        paddingVertical: 12,
        borderBottomWidth: StyleSheet.hairlineWidth,
    },
    headerTitle: {
        fontSize: 17,
        fontWeight: '600',
    },
    iconButton: {
        padding: 4,
        minWidth: 36,
        alignItems: 'center',
    },
    toast: {
        position: 'absolute',
        top: 60,
        alignSelf: 'center',
        flexDirection: 'row',
        alignItems: 'center',
        gap: 8,
        paddingHorizontal: 16,
        paddingVertical: 10,
        borderRadius: 99,
        zIndex: 100,
    },
    toastText: {
        color: '#FFFFFF',
        fontSize: 13,
        fontWeight: '600',
    },
    scrollContent: {
        paddingHorizontal: 20,
        paddingTop: 24,
    },
    hydrating: {
        alignItems: 'center',
        marginBottom: 20,
        gap: 8,
    },
    hydratingText: {
        fontSize: 13,
    },
    hero: {
        alignItems: 'center',
        marginBottom: 32,
    },
    statusBadge: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingHorizontal: 12,
        paddingVertical: 6,
        borderRadius: 99,
        marginBottom: 16,
    },
    statusDot: {
        width: 8,
        height: 8,
        borderRadius: 4,
        marginRight: 8,
    },
    statusText: {
        fontSize: 14,
        fontWeight: '600',
    },
    amount: {
        fontSize: 40,
        fontWeight: '800',
        letterSpacing: -1,
    },
    assetCode: {
        fontSize: 18,
        fontWeight: '600',
        marginTop: 4,
    },
    timestamp: {
        fontSize: 14,
        marginTop: 8,
    },
    section: {
        marginBottom: 24,
    },
    sectionTitle: {
        fontSize: 16,
        fontWeight: '700',
        marginBottom: 12,
    },
    card: {
        borderRadius: 16,
        borderWidth: 1,
        overflow: 'hidden',
    },
    receiptCard: {
        padding: 16,
        gap: 16,
    },
    receiptPreview: {
        borderRadius: 24,
        padding: 20,
        overflow: 'hidden',
        gap: 10,
    },
    receiptGlow: {
        position: 'absolute',
        top: -40,
        right: -30,
        width: 180,
        height: 180,
        borderRadius: 90,
        backgroundColor: 'rgba(255,255,255,0.16)',
    },
    receiptEyebrow: {
        color: 'rgba(255,255,255,0.72)',
        fontSize: 12,
        fontWeight: '700',
        letterSpacing: 1,
        textTransform: 'uppercase',
    },
    receiptAmount: {
        color: '#FFFFFF',
        fontSize: 28,
        fontWeight: '800',
    },
    receiptStatus: {
        color: 'rgba(255,255,255,0.84)',
        fontSize: 14,
        fontWeight: '600',
    },
    receiptPreviewRows: {
        marginTop: 8,
        gap: 6,
    },
    receiptPreviewRow: {
        color: 'rgba(255,255,255,0.88)',
        fontSize: 13,
        lineHeight: 18,
    },
    receiptLinkPreview: {
        marginTop: 10,
        color: 'rgba(255,255,255,0.74)',
        fontSize: 12,
        lineHeight: 18,
    },
    receiptActionsRow: {
        flexDirection: 'row',
        gap: 12,
    },
    secondaryActionButton: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        borderRadius: 16,
        borderWidth: 1,
        paddingVertical: 14,
        paddingHorizontal: 12,
    },
    secondaryActionText: {
        fontSize: 14,
        fontWeight: '700',
    },
    privacySection: {
        borderRadius: 20,
        overflow: 'hidden',
    },
    privacyTitle: {
        fontSize: 15,
        fontWeight: '700',
        marginBottom: 10,
    },
    privacyRow: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingVertical: 14,
        borderBottomWidth: StyleSheet.hairlineWidth,
        gap: 12,
    },
    privacyCopy: {
        flex: 1,
        gap: 4,
    },
    privacyLabel: {
        fontSize: 14,
        fontWeight: '600',
    },
    privacyDescription: {
        fontSize: 12,
        lineHeight: 17,
    },
    timelinePadding: {
        padding: 16,
    },
    shareButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 10,
        paddingVertical: 14,
        borderRadius: 14,
        marginTop: 8,
    },
    shareButtonText: {
        fontSize: 15,
        fontWeight: '700',
    },
    explorerLink: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        marginTop: 20,
        paddingVertical: 8,
    },
    explorerText: {
        fontSize: 14,
        fontWeight: '500',
    },
});
