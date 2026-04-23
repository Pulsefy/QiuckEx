import React from 'react';
import {
    View,
    Text,
    StyleSheet,
    ScrollView,
    TouchableOpacity,
    Alert,
    Share,
} from 'react-native';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as Clipboard from 'expo-clipboard';
import { Ionicons } from '@expo/vector-icons';
import { useTheme } from '../../src/theme/ThemeContext';

/**
 * Mock data for demonstration of "high-signal" features (events, timeline).
 * In a real app, this would be fetched from an API.
 */
const MOCK_EVENTS = [
    {
        id: '1',
        type: 'webhook_delivery',
        status: 'success',
        title: 'Webhook Delivered',
        description: 'Sent to https://api.merchant.com/webhooks/payments',
        timestamp: '2026-04-23T10:45:00Z',
    },
    {
        id: '2',
        type: 'notification',
        status: 'success',
        title: 'Push Notification Sent',
        description: 'Sent to recipient device (iPhone 15 Pro)',
        timestamp: '2026-04-23T10:45:05Z',
    },
    {
        id: '3',
        type: 'system',
        status: 'pending',
        title: 'Reconciliation Pending',
        description: 'Waiting for daily settlement cycle',
        timestamp: '2026-04-23T10:50:00Z',
    }
];

export default function TransactionDetailScreen() {
    const { theme, isDark } = useTheme();
    const router = useRouter();
    const params = useLocalSearchParams<{
        id: string;
        amount: string;
        asset: string;
        memo?: string;
        timestamp: string;
        txHash: string;
        source: string;
        destination: string;
        status: string;
    }>();

    const handleCopy = async (text: string, label: string) => {
        await Clipboard.setStringAsync(text);
        Alert.alert('Copied', `${label} copied to clipboard.`);
    };

    const handleShare = async () => {
        try {
            await Share.share({
                message: `Transaction Details:\nAmount: ${params.amount} ${params.asset}\nHash: ${params.txHash}\nStatus: ${params.status}`,
            });
        } catch (error) {
            console.error(error);
        }
    };

    const formatDate = (iso: string) => {
        return new Date(iso).toLocaleString('en-US', {
            month: 'long',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        });
    };

    const shorten = (str: string) => (str ? `${str.slice(0, 10)}...${str.slice(-10)}` : 'N/A');

    return (
        <SafeAreaView style={[styles.container, { backgroundColor: theme.surface }]} edges={['top', 'bottom']}>
            {/* Header */}
            <View style={[styles.header, { borderBottomColor: theme.border }]}>
                <TouchableOpacity onPress={() => router.back()} style={styles.iconButton}>
                    <Ionicons name="chevron-back" size={24} color={theme.textPrimary} />
                </TouchableOpacity>
                <Text style={[styles.headerTitle, { color: theme.textPrimary }]}>Transaction Receipt</Text>
                <TouchableOpacity onPress={handleShare} style={styles.iconButton}>
                    <Ionicons name="share-outline" size={24} color={theme.textPrimary} />
                </TouchableOpacity>
            </View>

            <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={styles.scrollContent}>
                {/* Hero Section */}
                <View style={styles.hero}>
                    <View style={[styles.statusBadge, { backgroundColor: params.status === 'Success' ? theme.status.success + '20' : theme.status.warning + '20' }]}>
                        <View style={[styles.statusDot, { backgroundColor: params.status === 'Success' ? theme.status.success : theme.status.warning }]} />
                        <Text style={[styles.statusText, { color: params.status === 'Success' ? theme.status.success : theme.status.warning }]}>
                            {params.status || 'Pending'}
                        </Text>
                    </View>
                    <Text style={[styles.amount, { color: theme.textPrimary }]}>
                        {parseFloat(params.amount || '0').toFixed(2)}
                    </Text>
                    <Text style={[styles.assetCode, { color: theme.textSecondary }]}>{params.asset}</Text>
                    <Text style={[styles.timestamp, { color: theme.textMuted }]}>{formatDate(params.timestamp)}</Text>
                </View>

                {/* Timeline Section */}
                <View style={styles.section}>
                    <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>Status Timeline</Text>
                    <View style={styles.timeline}>
                        <TimelineStep 
                            title="Initiated" 
                            time={formatDate(params.timestamp)} 
                            isLast={false} 
                            isCompleted={true} 
                            theme={theme} 
                        />
                        <TimelineStep 
                            title="Validated on Network" 
                            time={formatDate(params.timestamp)} 
                            isLast={false} 
                            isCompleted={true} 
                            theme={theme} 
                        />
                        <TimelineStep 
                            title={params.status === 'Success' ? 'Completed' : 'Processing'} 
                            time={params.status === 'Success' ? formatDate(params.timestamp) : 'In Progress...'} 
                            isLast={true} 
                            isCompleted={params.status === 'Success'} 
                            theme={theme} 
                        />
                    </View>
                </View>

                {/* Details Section */}
                <View style={styles.section}>
                    <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>Details</Text>
                    <View style={[styles.card, { backgroundColor: theme.surfaceElevated, borderColor: theme.border }]}>
                        <DetailRow label="Sender" value={shorten(params.source)} onCopy={() => handleCopy(params.source, 'Sender Address')} theme={theme} />
                        <DetailRow label="Recipient" value={shorten(params.destination)} onCopy={() => handleCopy(params.destination, 'Recipient Address')} theme={theme} />
                        <DetailRow label="Memo" value={params.memo || 'None'} theme={theme} />
                        <DetailRow label="Transaction Hash" value={shorten(params.txHash)} onCopy={() => handleCopy(params.txHash, 'Transaction Hash')} isLast theme={theme} />
                    </View>
                </View>

                {/* Related Events Section */}
                <View style={styles.section}>
                    <View style={styles.sectionHeader}>
                        <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>Related Events</Text>
                        <View style={[styles.betaBadge, { backgroundColor: theme.primary + '20' }]}>
                            <Text style={[styles.betaText, { color: theme.primary }]}>Support View</Text>
                        </View>
                    </View>
                    {MOCK_EVENTS.map((event, index) => (
                        <EventItem 
                            key={event.id} 
                            event={event} 
                            isLast={index === MOCK_EVENTS.length - 1} 
                            theme={theme} 
                        />
                    ))}
                </View>

                <View style={{ height: 40 }} />
            </ScrollView>
        </SafeAreaView>
    );
}

function TimelineStep({ title, time, isLast, isCompleted, theme }: any) {
    return (
        <View style={styles.timelineStep}>
            <View style={styles.timelineLeft}>
                <View style={[styles.timelineDot, { backgroundColor: isCompleted ? theme.status.success : theme.border }]}>
                    {isCompleted && <Ionicons name="checkmark" size={10} color="white" />}
                </View>
                {!isLast && <View style={[styles.timelineLine, { backgroundColor: theme.border }]} />}
            </View>
            <View style={styles.timelineRight}>
                <Text style={[styles.timelineTitle, { color: theme.textPrimary }]}>{title}</Text>
                <Text style={[styles.timelineTime, { color: theme.textMuted }]}>{time}</Text>
            </View>
        </View>
    );
}

function DetailRow({ label, value, onCopy, isLast, theme }: any) {
    return (
        <View style={[styles.detailRow, !isLast && { borderBottomColor: theme.border, borderBottomWidth: StyleSheet.hairlineWidth }]}>
            <View style={styles.detailLeft}>
                <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>{label}</Text>
                <Text style={[styles.detailValue, { color: theme.textPrimary }]}>{value}</Text>
            </View>
            {onCopy && (
                <TouchableOpacity onPress={onCopy} style={styles.copyButton}>
                    <Ionicons name="copy-outline" size={18} color={theme.primary} />
                </TouchableOpacity>
            )}
        </View>
    );
}

function EventItem({ event, isLast, theme }: any) {
    return (
        <View style={[styles.eventItem, { backgroundColor: theme.surfaceElevated, borderColor: theme.border }, isLast && { marginBottom: 0 }]}>
            <View style={styles.eventHeader}>
                <View style={[styles.eventIcon, { backgroundColor: event.status === 'success' ? theme.status.success + '20' : theme.status.warning + '20' }]}>
                    <Ionicons 
                        name={event.type === 'webhook_delivery' ? 'globe-outline' : event.type === 'notification' ? 'notifications-outline' : 'settings-outline'} 
                        size={16} 
                        color={event.status === 'success' ? theme.status.success : theme.status.warning} 
                    />
                </View>
                <View style={styles.eventInfo}>
                    <Text style={[styles.eventTitle, { color: theme.textPrimary }]}>{event.title}</Text>
                    <Text style={[styles.eventTime, { color: theme.textMuted }]}>{new Date(event.timestamp).toLocaleTimeString()}</Text>
                </View>
                <View style={[styles.eventStatusBadge, { backgroundColor: event.status === 'success' ? theme.status.success + '20' : theme.status.warning + '20' }]}>
                    <Text style={[styles.eventStatusText, { color: event.status === 'success' ? theme.status.success : theme.status.warning }]}>
                        {event.status.toUpperCase()}
                    </Text>
                </View>
            </View>
            <Text style={[styles.eventDescription, { color: theme.textSecondary }]}>{event.description}</Text>
        </View>
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
    },
    scrollContent: {
        paddingHorizontal: 20,
        paddingTop: 24,
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
    sectionHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 12,
        gap: 8,
    },
    sectionTitle: {
        fontSize: 16,
        fontWeight: '700',
        marginBottom: 12,
    },
    betaBadge: {
        paddingHorizontal: 8,
        paddingVertical: 2,
        borderRadius: 4,
        marginBottom: 12,
    },
    betaText: {
        fontSize: 10,
        fontWeight: '800',
        textTransform: 'uppercase',
    },
    timeline: {
        paddingLeft: 4,
    },
    timelineStep: {
        flexDirection: 'row',
    },
    timelineLeft: {
        width: 24,
        alignItems: 'center',
    },
    timelineDot: {
        width: 18,
        height: 18,
        borderRadius: 9,
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1,
    },
    timelineLine: {
        width: 2,
        flex: 1,
        marginVertical: -2,
    },
    timelineRight: {
        flex: 1,
        paddingLeft: 12,
        paddingBottom: 24,
    },
    timelineTitle: {
        fontSize: 15,
        fontWeight: '600',
    },
    timelineTime: {
        fontSize: 13,
        marginTop: 2,
    },
    card: {
        borderRadius: 16,
        borderWidth: 1,
        overflow: 'hidden',
    },
    detailRow: {
        flexDirection: 'row',
        alignItems: 'center',
        padding: 16,
    },
    detailLeft: {
        flex: 1,
    },
    detailLabel: {
        fontSize: 12,
        fontWeight: '600',
        marginBottom: 4,
        textTransform: 'uppercase',
    },
    detailValue: {
        fontSize: 14,
        fontFamily: 'monospace',
    },
    copyButton: {
        padding: 8,
    },
    eventItem: {
        borderRadius: 12,
        borderWidth: 1,
        padding: 12,
        marginBottom: 12,
    },
    eventHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 8,
    },
    eventIcon: {
        width: 28,
        height: 28,
        borderRadius: 14,
        alignItems: 'center',
        justifyContent: 'center',
        marginRight: 10,
    },
    eventInfo: {
        flex: 1,
    },
    eventTitle: {
        fontSize: 14,
        fontWeight: '600',
    },
    eventTime: {
        fontSize: 11,
    },
    eventStatusBadge: {
        paddingHorizontal: 6,
        paddingVertical: 2,
        borderRadius: 4,
    },
    eventStatusText: {
        fontSize: 10,
        fontWeight: '700',
    },
    eventDescription: {
        fontSize: 13,
        lineHeight: 18,
    },
});
