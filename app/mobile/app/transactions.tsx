import { useLocalSearchParams, useRouter } from 'expo-router';
import React from 'react';
import {
    View,
    Text,
    StyleSheet,
    FlatList,
    RefreshControl,
    TouchableOpacity,
    ActivityIndicator,
    ListRenderItemInfo,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import TransactionItem from '../components/transaction-item';
import { useTransactions } from '../hooks/use-transactions';
import type { TransactionItem as TransactionItemType } from '../types/transaction';

/**
 * Placeholder account used when no accountId is passed via route params.
 * Replace this with the real wallet address once the wallet-connect flow
 * persists the key.
 */
const DEMO_ACCOUNT_ID =
    'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN';

// ─── Loading Skeleton ────────────────────────────────────────────────────────

function SkeletonRow() {
    return (
        <View style={skeleton.row}>
            <View style={skeleton.circle} />
            <View style={skeleton.lines}>
                <View style={[skeleton.line, { width: '55%' }]} />
                <View style={[skeleton.line, { width: '35%', marginTop: 6 }]} />
            </View>
            <View style={[skeleton.line, { width: 60, alignSelf: 'center' }]} />
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
        borderBottomColor: '#E5E7EB',
    },
    circle: {
        width: 44,
        height: 44,
        borderRadius: 22,
        backgroundColor: '#E5E7EB',
        marginRight: 14,
    },
    lines: { flex: 1 },
    line: {
        height: 12,
        borderRadius: 6,
        backgroundColor: '#E5E7EB',
    },
});

// ─── Main Screen ─────────────────────────────────────────────────────────────

export default function TransactionsScreen() {
    const router = useRouter();
    const params = useLocalSearchParams<{ accountId?: string }>();
    const accountId = (params.accountId ?? DEMO_ACCOUNT_ID).trim();

    const { transactions, loading, refreshing, error, hasMore, refresh, loadMore } =
        useTransactions(accountId);

    const shortAccount = `${accountId.slice(0, 6)}…${accountId.slice(-4)}`;

    const renderItem = ({ item }: ListRenderItemInfo<TransactionItemType>) => (
        <TransactionItem item={item} accountId={accountId} />
    );

    const ListHeader = (
        <View style={styles.listHeader}>
            <Text style={styles.accountPill}>{shortAccount}</Text>
        </View>
    );

    const ListEmpty = loading ? (
        <View>
            {[...Array(6)].map((_, i) => (
                <SkeletonRow key={i} />
            ))}
        </View>
    ) : (
        <View style={styles.emptyContainer}>
            <Text style={styles.emptyIcon}>📭</Text>
            <Text style={styles.emptyTitle}>No transactions yet</Text>
            <Text style={styles.emptySubtitle}>
                Payments sent or received to this account will appear here.
            </Text>
        </View>
    );

    const ListFooter = hasMore ? (
        <View style={styles.footer}>
            <ActivityIndicator size="small" color="#6B7280" />
        </View>
    ) : null;

    return (
        <SafeAreaView style={styles.container} edges={['top', 'bottom']}>
            {/* ── Header ── */}
            <View style={styles.header}>
                <TouchableOpacity
                    onPress={() => router.back()}
                    style={styles.backBtn}
                    hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
                >
                    <Text style={styles.backChevron}>‹</Text>
                </TouchableOpacity>
                <Text style={styles.headerTitle}>Transaction History</Text>
                <View style={styles.backBtn} />
            </View>

            {/* ── Error Banner ── */}
            {error ? (
                <View style={styles.errorBanner}>
                    <Text style={styles.errorText} numberOfLines={2}>
                        {error}
                    </Text>
                    <TouchableOpacity onPress={refresh} style={styles.retryBtn}>
                        <Text style={styles.retryText}>Retry</Text>
                    </TouchableOpacity>
                </View>
            ) : null}

            {/* ── Transaction List ── */}
            <FlatList<TransactionItemType>
                data={transactions}
                keyExtractor={item => item.pagingToken}
                renderItem={renderItem}
                ListHeaderComponent={ListHeader}
                ListEmptyComponent={ListEmpty}
                ListFooterComponent={ListFooter}
                refreshControl={
                    <RefreshControl
                        refreshing={refreshing}
                        onRefresh={refresh}
                        tintColor="#6B7280"
                    />
                }
                onEndReached={loadMore}
                onEndReachedThreshold={0.8}
                contentContainerStyle={
                    transactions.length === 0 && !loading
                        ? styles.emptyFill
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
        backgroundColor: '#F9FAFB',
    },

    // Header
    header: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingHorizontal: 16,
        paddingVertical: 12,
        backgroundColor: '#fff',
        borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: '#E5E7EB',
    },
    headerTitle: {
        fontSize: 17,
        fontWeight: '600',
        color: '#111827',
    },
    backBtn: {
        width: 36,
        alignItems: 'center',
    },
    backChevron: {
        fontSize: 28,
        color: '#111827',
        lineHeight: 32,
    },

    // Error banner
    errorBanner: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: '#FEF2F2',
        borderBottomWidth: 1,
        borderBottomColor: '#FECACA',
        paddingHorizontal: 16,
        paddingVertical: 10,
        gap: 12,
    },
    errorText: {
        flex: 1,
        fontSize: 13,
        color: '#991B1B',
        lineHeight: 18,
    },
    retryBtn: {
        backgroundColor: '#DC2626',
        borderRadius: 6,
        paddingHorizontal: 14,
        paddingVertical: 6,
    },
    retryText: {
        color: '#fff',
        fontSize: 13,
        fontWeight: '600',
    },

    // List header
    listHeader: {
        paddingHorizontal: 20,
        paddingTop: 16,
        paddingBottom: 8,
    },
    accountPill: {
        alignSelf: 'flex-start',
        backgroundColor: '#E5E7EB',
        color: '#374151',
        fontSize: 12,
        fontWeight: '600',
        paddingHorizontal: 10,
        paddingVertical: 4,
        borderRadius: 99,
        overflow: 'hidden',
        fontFamily: 'monospace',
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
        color: '#111827',
        marginBottom: 8,
        textAlign: 'center',
    },
    emptySubtitle: {
        fontSize: 14,
        color: '#6B7280',
        textAlign: 'center',
        lineHeight: 20,
    },

    // Footer (load-more indicator)
    footer: {
        paddingVertical: 20,
        alignItems: 'center',
    },
});
