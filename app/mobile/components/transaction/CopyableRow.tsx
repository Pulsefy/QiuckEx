import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import * as Haptics from 'expo-haptics';
import type { ThemeTokens } from '../../src/theme/tokens';

interface CopyableRowProps {
    label: string;
    value: string;
    rawValue?: string;
    theme: ThemeTokens;
    isLast?: boolean;
    onCopy?: () => void;
    icon?: keyof typeof Ionicons.glyphMap;
}

export function CopyableRow({
    label,
    value,
    rawValue,
    theme,
    isLast = false,
    onCopy,
    icon = 'copy-outline',
}: CopyableRowProps) {
    const handleCopy = async () => {
        const textToCopy = rawValue ?? value;
        if (!textToCopy || textToCopy === 'None' || textToCopy === 'N/A') return;

        await Clipboard.setStringAsync(textToCopy);
        await Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
        if (onCopy) onCopy();
    };

    const canCopy = Boolean(rawValue ?? value) && value !== 'None' && value !== 'N/A';

    return (
        <View
            style={[
                styles.row,
                !isLast && {
                    borderBottomColor: theme.border,
                    borderBottomWidth: StyleSheet.hairlineWidth,
                },
            ]}
        >
            <View style={styles.left}>
                <Text style={[styles.label, { color: theme.textSecondary }]}>
                    {label}
                </Text>
                <Text
                    style={[
                        styles.value,
                        { color: theme.textPrimary },
                        canCopy && styles.valueMonospace,
                    ]}
                    selectable
                >
                    {value}
                </Text>
            </View>
            {canCopy && (
                <TouchableOpacity
                    onPress={handleCopy}
                    style={styles.copyBtn}
                    activeOpacity={0.6}
                    hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
                    accessibilityLabel={`Copy ${label}`}
                    accessibilityRole="button"
                >
                    <Ionicons name={icon} size={18} color={theme.primary} />
                </TouchableOpacity>
            )}
        </View>
    );
}

const styles = StyleSheet.create({
    row: {
        flexDirection: 'row',
        alignItems: 'center',
        padding: 16,
    },
    left: {
        flex: 1,
    },
    label: {
        fontSize: 12,
        fontWeight: '600',
        marginBottom: 4,
        textTransform: 'uppercase',
        letterSpacing: 0.5,
    },
    value: {
        fontSize: 14,
        lineHeight: 20,
    },
    valueMonospace: {
        fontFamily: 'monospace',
    },
    copyBtn: {
        padding: 8,
        marginLeft: 8,
    },
});
