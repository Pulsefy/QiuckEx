import React from 'react';
import { StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { ThemedText } from '../themed-text';
import { ThemedView } from '../themed-view';
import { useThemeColor } from '../../hooks/use-theme-color';

interface EmptyStateProps {
    title?: string;
    message?: string;
    icon?: keyof typeof Ionicons.glyphMap;
}

/**
 * A reusable component to display when there is no data to show.
 */
export function EmptyState({
    title = 'No data found',
    message = 'There is nothing to display at the moment.',
    icon = 'document-text-outline',
}: EmptyStateProps) {
    const iconColor = useThemeColor({}, 'tabIconDefault');

    return (
        <ThemedView style={styles.container}>
            <Ionicons name={icon} size={64} color={iconColor} style={styles.icon} />
            <ThemedText type="subtitle" style={styles.title}>
                {title}
            </ThemedText>
            <ThemedText style={styles.message}>
                {message}
            </ThemedText>
        </ThemedView>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        padding: 32,
        minHeight: 300,
    },
    icon: {
        marginBottom: 24,
        opacity: 0.4,
    },
    title: {
        marginBottom: 12,
        textAlign: 'center',
    },
    message: {
        textAlign: 'center',
        opacity: 0.5,
        lineHeight: 20,
    },
});
