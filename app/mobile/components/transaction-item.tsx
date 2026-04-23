import React from 'react';
import {
    View,
    Text,
    StyleSheet,
    TouchableOpacity,
    Clipboard,
} from 'react-native';
import type { TransactionItem as TransactionItemType } from '../types/transaction';
import { useRouter } from 'expo-router';
import { Ionicons } from '@expo/vector-icons';
import { useTheme } from '../src/theme/ThemeContext';

interface Props {
    item: TransactionItemType;
    /** The connected account ID used to determine payment direction */
    accountId: string;
}

function formatDate(iso: string): string {
    const d = new Date(iso);
    return d.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

function formatAsset(asset: string): string {
    // If asset is "CODE:ISSUER" → show "CODE"
    const colonIdx = asset.indexOf(':');
    return colonIdx === -1 ? asset : asset.slice(0, colonIdx);
}

function shortenHash(hash: string): string {
    return `${hash.slice(0, 6)}…${hash.slice(-6)}`;
}

function shortenAddress(address: string): string {
    if (address.length <= 12) return address;
    return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

export default function TransactionItem({ item }: Props) {
    const { theme } = useTheme();
    const router = useRouter();
    const assetLabel = formatAsset(item.asset);
    const hasAddresses = Boolean(item.source || item.destination);

    const handlePress = () => {
        router.push({
            pathname: `/transaction/${item.pagingToken}`,
            params: {
                id: item.pagingToken,
                amount: item.amount,
                asset: item.asset,
                memo: item.memo || '',
                timestamp: item.timestamp,
                txHash: item.txHash,
                source: item.source || '',
                destination: item.destination || '',
                status: item.status || 'Success',
            }
        });
    };

    return (
        <TouchableOpacity 
            onPress={handlePress}
            activeOpacity={0.7}
            style={[styles.row, { borderBottomColor: theme.border, backgroundColor: theme.surfaceElevated }]}
        >
            {/* Left: icon + asset */}
            <View style={[styles.iconWrap, { backgroundColor: theme.surface }]}>
                <Text style={[styles.assetIcon, { color: theme.textPrimary }]}>{assetLabel.slice(0, 3)}</Text>
            </View>

            {/* Middle: asset name, memo, date */}
            <View style={styles.middle}>
                <Text style={[styles.assetName, { color: theme.textPrimary }]}>
                    {assetLabel}
                </Text>
                {item.memo ? (
                    <Text style={[styles.memo, { color: theme.textSecondary }]} numberOfLines={1}>
                        {item.memo}
                    </Text>
                ) : null}
                <Text style={[styles.txHash, { color: theme.textMuted }]}>{shortenHash(item.txHash)}</Text>
                {hasAddresses ? (
                    <Text style={[styles.address, { color: theme.textSecondary }]} numberOfLines={1}>
                        {shortenAddress(item.source)} → {shortenAddress(item.destination)}
                    </Text>
                ) : null}
                <Text style={[styles.date, { color: theme.textMuted }]}>{formatDate(item.timestamp)}</Text>
            </View>

            {/* Right: amount */}
            <View style={styles.right}>
                <Text style={[styles.amount, { color: theme.textPrimary }]} numberOfLines={1} adjustsFontSizeToFit>
                    {parseFloat(item.amount).toFixed(2)}
                </Text>
                <Text style={[styles.assetCode, { color: theme.textSecondary }]}>{assetLabel}</Text>
                <Ionicons name="chevron-forward" size={16} color={theme.textMuted} style={{ marginTop: 4 }} />
            </View>
        </TouchableOpacity>
    );
}

const styles = StyleSheet.create({
    row: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingHorizontal: 20,
        paddingVertical: 14,
        borderBottomWidth: StyleSheet.hairlineWidth,
    },
    iconWrap: {
        width: 44,
        height: 44,
        borderRadius: 22,
        alignItems: 'center',
        justifyContent: 'center',
        marginRight: 14,
    },
    assetIcon: {
        fontSize: 13,
        fontWeight: '700',
        letterSpacing: -0.5,
    },
    middle: {
        flex: 1,
        gap: 2,
    },
    assetName: {
        fontSize: 15,
        fontWeight: '600',
    },
    memo: {
        fontSize: 13,
    },
    txHash: {
        fontSize: 11,
        fontFamily: 'monospace',
    },
    address: {
        fontSize: 11,
        fontFamily: 'monospace',
    },
    date: {
        fontSize: 12,
        marginTop: 1,
    },
    right: {
        alignItems: 'flex-end',
        marginLeft: 8,
        maxWidth: 110,
    },
    amount: {
        fontSize: 15,
        fontWeight: '700',
    },
    assetCode: {
        fontSize: 12,
        marginTop: 2,
    },
});
