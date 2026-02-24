import React from 'react';
import { StyleSheet, View, TouchableOpacity } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { ThemedText } from '../themed-text';
import { ThemedView } from '../themed-view';
import { useThemeColor } from '../../hooks/use-theme-color';

interface ErrorStateProps {
    title?: string;
    message?: string;
    icon?: keyof typeof Ionicons.glyphMap;
    onRetry?: () => void;
    retryLabel?: string;
}

/**
 * A reusable component to display an error message and a retry button.
 */
export function ErrorState({
    title = 'Something went wrong',
    message = 'We encountered an error while loading the data. Please try again.',
    icon = 'alert-circle-outline',
    onRetry,
    retryLabel = 'Try Again',
}: ErrorStateProps) {
    const tintColor = useThemeColor({}, 'tint');

    return (
        <ThemedView style={styles.container}>
            <Ionicons name={icon} size={64} color={tintColor} style={styles.icon} />
            <ThemedText type="subtitle" style={styles.title}>
                {title}
            </ThemedText>
            <ThemedText style={styles.message}>
                {message}
            </ThemedText>

            {onRetry && (
                <TouchableOpacity
                    style={[styles.button, { backgroundColor: tintColor }]}
                    onPress={onRetry}
                    activeOpacity={0.7}
                >
                    <ThemedText style={styles.buttonText}>{retryLabel}</ThemedText>
                </TouchableOpacity>
            )}
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
        opacity: 0.8,
    },
    title: {
        marginBottom: 12,
        textAlign: 'center',
    },
    message: {
        textAlign: 'center',
        opacity: 0.6,
        marginBottom: 32,
        lineHeight: 20,
    },
    button: {
        paddingVertical: 12,
        paddingHorizontal: 32,
        borderRadius: 12,
        elevation: 2,
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.1,
        shadowRadius: 4,
    },
    buttonText: {
        color: '#FFFFFF',
        fontWeight: '700',
        fontSize: 16,
    },
});
