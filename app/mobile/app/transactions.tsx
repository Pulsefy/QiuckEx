import { useLocalSearchParams, useRouter } from 'expo-router';
import React from 'react';
import {
    View,
    Text,
    StyleSheet,
    RefreshControl,
    TouchableOpacity,
    ActivityIndicator,
    TextInput,
    ScrollView,
    Pressable,
    Alert,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { FlashList, type ListRenderItemInfo } from '@shopify/flash-list';
import * as FileSystem from 'expo-file-system';
import * as Sharing from 'expo-sharing';

import TransactionItem from '../components/transaction-item';
import { useNotifications } from '../components/notifications/NotificationContext';
import { useTransactions } from '../hooks/use-transactions';
import type { TransactionItem as TransactionItemType } from '../types/transaction';
import { ErrorState } from '../components/resilience/error-state';
import { EmptyState } from '../components/resilience/empty-state';
import { useTheme } from '../src/theme/ThemeContext';

const fileSystemCompat = FileSystem as typeof FileSystem & {
    cacheDirectory?: string | null;
    EncodingType?: {
        UTF8: string;
    };
};

/**
 * Placeholder account used when no accountId is passed via route params.
 */
const DEMO_ACCOUNT_ID =
    'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN';

const STATUS_FILTERS = ['All', 'Success', 'Pending'] as const;

function getAssetCode(asset: string): string {
    const colonIdx = asset.indexOf(':');
    return colonIdx === -1 ? asset : asset.slice(0, colonIdx);
}

function parseDateInput(value: string, endOfDay: boolean): number | null {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(trimmed);
    if (!match) return null;
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const date = new Date(year, month - 1, day);
    if (Number.isNaN(date.getTime())) return null;
    if (endOfDay) {
        date.setHours(23, 59, 59, 999);
    } else {
        date.setHours(0, 0, 0, 0);
    }
    return date.getTime();
}

function escapeCsvValue(value: string): string {
    if (value.includes('"') || value.includes(',') || value.includes('\n')) {
        return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
}

// ─── Loading Skeleton ────────────────────────────────────────────────────────

function SkeletonRow() {
    const { theme } = useTheme();
    return (
        <View style={[skeleton.row, { borderBottomColor: theme.border }]}>
            <View style={[skeleton.circle, { backgroundColor: theme.skeleton }]} />
            <View style={skeleton.lines}>
                <View style={[skeleton.line, { width: '55%', backgroundColor: theme.skeleton }]} />
                <View style={[skeleton.line, { width: '35%', marginTop: 6, backgroundColor: theme.skeleton }]} />
            </View>
            <View style={[skeleton.line, { width: 60, alignSelf: 'center', backgroundColor: theme.skeleton }]} />
        </View>
    );
}

const skeleton = StyleSheet.create({
    row: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingHorizontal: 20,
        paddingVertical: 14,
        borderBottomWidth: StyleSheet.hairlineWidth,
    },
    circle: {
        width: 44,
        height: 44,
        borderRadius: 22,
        marginRight: 14,
    },
    lines: { flex: 1 },
    line: {
        height: 12,
        borderRadius: 6,
    },
});

// ─── Main Screen ─────────────────────────────────────────────────────────────

export default function TransactionsScreen() {
    const router = useRouter();
    const { theme } = useTheme();
    const { currentAccountId } = useNotifications();
    const params = useLocalSearchParams<{ accountId?: string }>();
    const accountId = (params.accountId ?? currentAccountId ?? DEMO_ACCOUNT_ID).trim();

    const { transactions, loading, refreshing, error, hasMore, refresh, loadMore } =
        useTransactions(accountId);

    const [searchQuery, setSearchQuery] = React.useState('');
    const deferredQuery = React.useDeferredValue(searchQuery);
    const [assetFilter, setAssetFilter] = React.useState<string>('All');
    const [statusFilter, setStatusFilter] = React.useState<(typeof STATUS_FILTERS)[number]>('All');
    const [dateFrom, setDateFrom] = React.useState('');
    const [dateTo, setDateTo] = React.useState('');

    const assetOptions = React.useMemo(() => {
        const codes = new Set<string>();
        transactions.forEach(item => codes.add(getAssetCode(item.asset)));
        return ['All', ...Array.from(codes).sort()];
    }, [transactions]);

    const fromMs = React.useMemo(() => parseDateInput(dateFrom, false), [dateFrom]);
    const toMs = React.useMemo(() => parseDateInput(dateTo, true), [dateTo]);

    const filteredTransactions = React.useMemo(() => {
        const query = deferredQuery.trim().toLowerCase();

        return transactions.filter(item => {
            if (assetFilter !== 'All' && getAssetCode(item.asset) !== assetFilter) {
                return false;
            }

            const itemStatus = item.status ?? 'Success';
            if (statusFilter !== 'All' && itemStatus !== statusFilter) {
                return false;
            }

            const timestampMs = Date.parse(item.timestamp);
            if (fromMs !== null && !Number.isNaN(timestampMs) && timestampMs < fromMs) {
                return false;
            }
            if (toMs !== null && !Number.isNaN(timestampMs) && timestampMs > toMs) {
                return false;
            }

            if (!query) return true;

            const memo = (item.memo ?? '').toLowerCase();
            const source = (item.source ?? '').toLowerCase();
            const destination = (item.destination ?? '').toLowerCase();
            const hash = item.txHash.toLowerCase();
            const asset = getAssetCode(item.asset).toLowerCase();

            return (
                memo.includes(query) ||
                source.includes(query) ||
                destination.includes(query) ||
                hash.includes(query) ||
                asset.includes(query)
            );
        });
    }, [transactions, deferredQuery, assetFilter, statusFilter, fromMs, toMs]);

    const filtersActive =
        searchQuery.trim().length > 0 ||
        assetFilter !== 'All' ||
        statusFilter !== 'All' ||
        dateFrom.trim().length > 0 ||
        dateTo.trim().length > 0;

    const shortAccount = `${accountId.slice(0, 6)}…${accountId.slice(-4)}`;

    const renderItem = ({ item }: any) => (
        <TransactionItem item={item} accountId={accountId} />
    );

    const handleExport = React.useCallback(async () => {
        if (filteredTransactions.length === 0) {
            Alert.alert('Nothing to export', 'There are no transactions matching your filters.');
            return;
        }

        const headers = [
            'timestamp',
            'amount',
            'asset',
            'memo',
            'txHash',
            'pagingToken',
            'source',
            'destination',
            'status',
        ];

        const rows = filteredTransactions.map(item => [
            item.timestamp,
            item.amount,
            item.asset,
            item.memo ?? '',
            item.txHash,
            item.pagingToken,
            item.source ?? '',
            item.destination ?? '',
            item.status ?? 'Success',
        ]);

        const csv = [headers, ...rows]
            .map(row => row.map(cell => escapeCsvValue(String(cell))).join(','))
            .join('\n');

        try {
            const fileName = `quickex-transactions-${new Date().toISOString().slice(0, 10)}.csv`;
            const cacheDirectory = fileSystemCompat.cacheDirectory ?? '';
            const fileUri = `${cacheDirectory}${fileName}`;

            await FileSystem.writeAsStringAsync(fileUri, csv, {
                encoding: 'utf8',
            });

            const canShare = await Sharing.isAvailableAsync();
            if (!canShare) {
                Alert.alert(
                    'Sharing not available',
                    'Sharing is not supported on this device.',
                );
                return;
            }

            await Sharing.shareAsync(fileUri, {
                mimeType: 'text/csv',
                dialogTitle: 'Export Transactions',
                UTI: 'public.comma-separated-values-text',
            });
        } catch (err) {
            const message = err instanceof Error ? err.message : 'Unable to export CSV.';
            Alert.alert('Export failed', message);
        }
    }, [filteredTransactions]);

    const handleClearFilters = React.useCallback(() => {
        setSearchQuery('');
        setAssetFilter('All');
        setStatusFilter('All');
        setDateFrom('');
        setDateTo('');
    }, []);

    const ListHeader = (
        <View style={styles.listHeader}>
            <View style={styles.headerRow}>
                <Text style={[styles.accountPill, { backgroundColor: theme.border, color: theme.textPrimary }]}>{shortAccount}</Text>
                <Text style={[styles.countLabel, { color: theme.textMuted }]}>
                    {filteredTransactions.length} of {transactions.length}
                </Text>
            </View>

            <View style={[styles.searchWrap, { backgroundColor: theme.surfaceElevated, borderColor: theme.border }]}>
                <TextInput
                    value={searchQuery}
                    onChangeText={setSearchQuery}
                    placeholder="Search memo, address, or hash"
                    placeholderTextColor={theme.inputPlaceholder}
                    style={[styles.searchInput, { color: theme.inputText }]}
                    returnKeyType="search"
                    autoCapitalize="none"
                    autoCorrect={false}
                    clearButtonMode="while-editing"
                />
            </View>

            <View style={styles.filterSection}>
                <Text style={[styles.filterLabel, { color: theme.textPrimary }]}>Asset Type</Text>
                <ScrollView horizontal showsHorizontalScrollIndicator={false}>
                    <View style={styles.chipRow}>
                        {assetOptions.map(option => {
                            const isActive = option === assetFilter;
                            return (
                                <Pressable
                                    key={option}
                                    onPress={() => setAssetFilter(option)}
                                    style={[
                                        styles.chip,
                                        { backgroundColor: theme.chipBg, borderColor: theme.border },
                                        isActive && { backgroundColor: theme.chipActiveBg, borderColor: theme.chipActiveBg },
                                    ]}
                                >
                                    <Text
                                        style={[
                                            styles.chipText,
                                            { color: theme.chipText },
                                            isActive && { color: theme.chipActiveText },
                                        ]}
                                    >
                                        {option}
                                    </Text>
                                </Pressable>
                            );
                        })}
                    </View>
                </ScrollView>
            </View>

            <View style={styles.filterSection}>
                <Text style={[styles.filterLabel, { color: theme.textPrimary }]}>Status</Text>
                <View style={styles.chipRow}>
                    {STATUS_FILTERS.map(option => {
                        const isActive = option === statusFilter;
                        return (
                            <Pressable
                                key={option}
                                onPress={() => setStatusFilter(option)}
                                style={[
                                    styles.chip,
                                    { backgroundColor: theme.chipBg, borderColor: theme.border },
                                    isActive && { backgroundColor: theme.chipActiveBg, borderColor: theme.chipActiveBg },
                                ]}
                            >
                                <Text
                                    style={[
                                        styles.chipText,
                                        { color: theme.chipText },
                                        isActive && { color: theme.chipActiveText },
                                    ]}
                                >
                                    {option}
                                </Text>
                            </Pressable>
                        );
                    })}
                </View>
            </View>

            <View style={styles.filterSection}>
                <Text style={[styles.filterLabel, { color: theme.textPrimary }]}>Date Range</Text>
                <View style={styles.dateRow}>
                    <View style={styles.dateInputWrap}>
                        <Text style={[styles.dateLabel, { color: theme.textMuted }]}>From</Text>
                        <TextInput
                            value={dateFrom}
                            onChangeText={setDateFrom}
                            placeholder="YYYY-MM-DD"
                            placeholderTextColor={theme.inputPlaceholder}
                            style={[styles.dateInput, { backgroundColor: theme.surfaceElevated, borderColor: theme.border, color: theme.inputText }]}
                            autoCapitalize="none"
                            autoCorrect={false}
                        />
                    </View>
                    <View style={styles.dateInputWrap}>
                        <Text style={[styles.dateLabel, { color: theme.textMuted }]}>To</Text>
                        <TextInput
                            value={dateTo}
                            onChangeText={setDateTo}
                            placeholder="YYYY-MM-DD"
                            placeholderTextColor={theme.inputPlaceholder}
                            style={[styles.dateInput, { backgroundColor: theme.surfaceElevated, borderColor: theme.border, color: theme.inputText }]}
                            autoCapitalize="none"
                            autoCorrect={false}
                        />
                    </View>
                </View>
                {(dateFrom && fromMs === null) || (dateTo && toMs === null) ? (
                    <Text style={[styles.dateHint, { color: theme.textMuted }]}>
                        Use the format YYYY-MM-DD (e.g. 2026-03-01).
                    </Text>
                ) : null}
            </View>

            <View style={styles.actionRow}>
                {filtersActive ? (
                    <Pressable onPress={handleClearFilters} style={styles.ghostButton}>
                        <Text style={[styles.ghostButtonText, { color: theme.textMuted }]}>Clear Filters</Text>
                    </Pressable>
                ) : (
                    <View />
                )}
                <Pressable onPress={handleExport} style={[styles.exportButton, { backgroundColor: theme.buttonPrimaryBg }]}>
                    <Text style={[styles.exportButtonText, { color: theme.buttonPrimaryText }]}>Export to CSV</Text>
                </Pressable>
            </View>
        </View>
    );

    const ListEmpty = loading ? (
        <View>
            {[...Array(6)].map((_, i) => (
                <SkeletonRow key={i} />
            ))}
        </View>
    ) : error ? (
        <ErrorState
            message={error}
            onRetry={refresh}
        />
    ) : filtersActive ? (
        <EmptyState
            title="No matching transactions"
            message="Try adjusting your filters or search terms."
            icon="filter-outline"
        />
    ) : (
        <EmptyState
            title="No transactions yet"
            message="Payments sent or received to this account will appear here."
            icon="receipt-outline"
        />
    );

    const ListFooter = hasMore ? (
        <View style={styles.footer}>
            <ActivityIndicator size="small" color={theme.textMuted} />
        </View>
    ) : null;

    return (
        <SafeAreaView style={[styles.container, { backgroundColor: theme.surface }]} edges={['top', 'bottom']}>
            {/* ── Header ── */}
            <View style={[styles.header, { backgroundColor: theme.headerBg, borderBottomColor: theme.border }]}>
                <TouchableOpacity
                    onPress={() => router.back()}
                    style={styles.backBtn}
                    hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
                >
                    <Text style={[styles.backChevron, { color: theme.textPrimary }]}>‹</Text>
                </TouchableOpacity>
                <Text style={[styles.headerTitle, { color: theme.textPrimary }]}>Transaction History</Text>
                <View style={styles.backBtn} />
            </View>

            {/* ── Transaction List ── */}
            <FlashList<TransactionItemType>
                data={filteredTransactions}
                keyExtractor={item => item.pagingToken}
                renderItem={renderItem}
                ListHeaderComponent={ListHeader}
                ListEmptyComponent={ListEmpty}
                ListFooterComponent={ListFooter}
                refreshControl={
                    <RefreshControl
                        refreshing={refreshing}
                        onRefresh={refresh}
                        tintColor={theme.textMuted}
                    />
                }
                onEndReached={loadMore}
                onEndReachedThreshold={0.8}
                estimatedItemSize={88}
                contentContainerStyle={
                    (filteredTransactions.length === 0 || error) && !loading
                        ? (styles.emptyFill as never)
                        : undefined
                }
                showsVerticalScrollIndicator={false}
            />
        </SafeAreaView>
    );
}

// ─── Styles ──────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
    container: {
        flex: 1,
    },

    // Header
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
    backBtn: {
        width: 36,
        alignItems: 'center',
    },
    backChevron: {
        fontSize: 28,
        lineHeight: 32,
    },

    // Error banner
    errorBanner: {
        flexDirection: 'row',
        alignItems: 'center',
        borderBottomWidth: 1,
        paddingHorizontal: 16,
        paddingVertical: 10,
        gap: 12,
    },
    errorText: {
        flex: 1,
        fontSize: 13,
        lineHeight: 18,
    },
    retryBtn: {
        borderRadius: 6,
        paddingHorizontal: 14,
        paddingVertical: 6,
    },
    retryText: {
        fontSize: 13,
        fontWeight: '600',
    },

    // List header
    listHeader: {
        paddingHorizontal: 20,
        paddingTop: 16,
        paddingBottom: 8,
        gap: 14,
    },
    headerRow: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
    },
    accountPill: {
        alignSelf: 'flex-start',
        fontSize: 12,
        fontWeight: '600',
        paddingHorizontal: 10,
        paddingVertical: 4,
        borderRadius: 99,
        overflow: 'hidden',
        fontFamily: 'monospace',
    },
    countLabel: {
        fontSize: 12,
        fontWeight: '600',
    },
    searchWrap: {
        borderRadius: 12,
        borderWidth: 1,
        paddingHorizontal: 12,
        paddingVertical: 8,
    },
    searchInput: {
        fontSize: 14,
    },
    filterSection: {
        gap: 8,
    },
    filterLabel: {
        fontSize: 12,
        fontWeight: '700',
        textTransform: 'uppercase',
        letterSpacing: 0.6,
    },
    chipRow: {
        flexDirection: 'row',
        gap: 8,
    },
    chip: {
        paddingHorizontal: 12,
        paddingVertical: 6,
        borderRadius: 999,
        borderWidth: 1,
    },
    chipText: {
        fontSize: 12,
        fontWeight: '600',
    },
    dateRow: {
        flexDirection: 'row',
        gap: 12,
    },
    dateInputWrap: {
        flex: 1,
        gap: 6,
    },
    dateLabel: {
        fontSize: 12,
        fontWeight: '600',
    },
    dateInput: {
        borderRadius: 10,
        borderWidth: 1,
        paddingHorizontal: 12,
        paddingVertical: 8,
        fontSize: 13,
    },
    dateHint: {
        fontSize: 11,
    },
    actionRow: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingBottom: 6,
    },
    ghostButton: {
        paddingHorizontal: 10,
        paddingVertical: 8,
    },
    ghostButtonText: {
        fontSize: 12,
        fontWeight: '600',
    },
    exportButton: {
        paddingHorizontal: 16,
        paddingVertical: 10,
        borderRadius: 10,
    },
    exportButtonText: {
        fontSize: 12,
        fontWeight: '700',
    },

    // Empty state
    emptyFill: {
        flexGrow: 1,
    },
    emptyContainer: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        paddingHorizontal: 40,
        paddingTop: 80,
    },
    emptyIcon: {
        fontSize: 48,
        marginBottom: 16,
    },
    emptyTitle: {
        fontSize: 18,
        fontWeight: '700',
        marginBottom: 8,
        textAlign: 'center',
    },
    emptySubtitle: {
        fontSize: 14,
        textAlign: 'center',
        lineHeight: 20,
    },

    // Footer (load-more indicator)
    footer: {
        paddingVertical: 20,
        alignItems: 'center',
    },
});
