import React from 'react';
import {
    View,
    Text,
    StyleSheet,
    TouchableOpacity,
    Clipboard,
} from 'react-native';
import type { TransactionItem as TransactionItemType } from '../types/transaction';

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

export default function TransactionItem({ item }: Props) {
    const assetLabel = formatAsset(item.asset);

    const handleCopyHash = () => {
        Clipboard.setString(item.txHash);
    };

    return (
        <View style={styles.row}>
            {/* Left: icon + asset */}
            <View style={styles.iconWrap}>
                <Text style={styles.assetIcon}>{assetLabel.slice(0, 3)}</Text>
            </View>

            {/* Middle: asset name, memo, date */}
            <View style={styles.middle}>
                <Text style={styles.assetName}>
                    {assetLabel}
                </Text>
                {item.memo ? (
                    <Text style={styles.memo} numberOfLines={1}>
                        {item.memo}
                    </Text>
                ) : null}
                <TouchableOpacity onPress={handleCopyHash} activeOpacity={0.6}>
                    <Text style={styles.txHash}>{shortenHash(item.txHash)}</Text>
                </TouchableOpacity>
                <Text style={styles.date}>{formatDate(item.timestamp)}</Text>
            </View>

            {/* Right: amount */}
            <View style={styles.right}>
                <Text style={styles.amount} numberOfLines={1} adjustsFontSizeToFit>
                    {parseFloat(item.amount).toFixed(2)}
                </Text>
                <Text style={styles.assetCode}>{assetLabel}</Text>
            </View>
        </View>
    );
}

const styles = StyleSheet.create({
    row: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingHorizontal: 20,
        paddingVertical: 14,
        borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: '#E5E7EB',
        backgroundColor: '#fff',
    },
    iconWrap: {
        width: 44,
        height: 44,
        borderRadius: 22,
        backgroundColor: '#F3F4F6',
        alignItems: 'center',
        justifyContent: 'center',
        marginRight: 14,
    },
    assetIcon: {
        fontSize: 13,
        fontWeight: '700',
        color: '#374151',
        letterSpacing: -0.5,
    },
    middle: {
        flex: 1,
        gap: 2,
    },
    assetName: {
        fontSize: 15,
        fontWeight: '600',
        color: '#111827',
    },
    memo: {
        fontSize: 13,
        color: '#6B7280',
    },
    txHash: {
        fontSize: 11,
        color: '#9CA3AF',
        fontFamily: 'monospace',
    },
    date: {
        fontSize: 12,
        color: '#9CA3AF',
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
        color: '#111827',
    },
    assetCode: {
        fontSize: 12,
        color: '#6B7280',
        marginTop: 2,
    },
});
