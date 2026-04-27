import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import type { ThemeTokens } from '../../src/theme/tokens';

export interface TimelineStep {
    title: string;
    subtitle?: string;
    time?: string;
    isCompleted: boolean;
    isActive?: boolean;
}

interface StatusTimelineProps {
    steps: TimelineStep[];
    theme: ThemeTokens;
}

export function StatusTimeline({ steps, theme }: StatusTimelineProps) {
    return (
        <View style={styles.container}>
            {steps.map((step, index) => {
                const isLast = index === steps.length - 1;
                const showActive = step.isActive || (!step.isCompleted && !step.isActive && index > 0);

                return (
                    <View key={index} style={styles.step}>
                        <View style={styles.leftColumn}>
                            <View
                                style={[
                                    styles.dot,
                                    {
                                        backgroundColor: step.isCompleted
                                            ? theme.status.success
                                            : showActive
                                                ? theme.primary
                                                : theme.border,
                                    },
                                ]}
                            >
                                {step.isCompleted && (
                                    <Ionicons name="checkmark" size={10} color="#FFFFFF" />
                                )}
                                {showActive && !step.isCompleted && (
                                    <View
                                        style={[
                                            styles.activeInnerDot,
                                            { backgroundColor: theme.primaryForeground },
                                        ]}
                                    />
                                )}
                            </View>
                            {!isLast && (
                                <View
                                    style={[
                                        styles.line,
                                        {
                                            backgroundColor: step.isCompleted
                                                ? theme.status.success
                                                : theme.border,
                                        },
                                    ]}
                                />
                            )}
                        </View>

                        <View style={[styles.rightColumn, !isLast && styles.rightColumnWithGap]}>
                            <Text
                                style={[
                                    styles.title,
                                    { color: theme.textPrimary },
                                ]}
                            >
                                {step.title}
                            </Text>
                            {step.subtitle ? (
                                <Text
                                    style={[
                                        styles.subtitle,
                                        { color: theme.textSecondary },
                                    ]}
                                >
                                    {step.subtitle}
                                </Text>
                            ) : null}
                            {step.time ? (
                                <Text
                                    style={[
                                        styles.time,
                                        { color: theme.textMuted },
                                    ]}
                                >
                                    {step.time}
                                </Text>
                            ) : null}
                        </View>
                    </View>
                );
            })}
        </View>
    );
}

const styles = StyleSheet.create({
    container: {
        paddingLeft: 4,
    },
    step: {
        flexDirection: 'row',
    },
    leftColumn: {
        width: 24,
        alignItems: 'center',
    },
    dot: {
        width: 20,
        height: 20,
        borderRadius: 10,
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1,
    },
    activeInnerDot: {
        width: 8,
        height: 8,
        borderRadius: 4,
    },
    line: {
        width: 2,
        flex: 1,
        marginVertical: -2,
    },
    rightColumn: {
        flex: 1,
        paddingLeft: 12,
        paddingBottom: 4,
    },
    rightColumnWithGap: {
        paddingBottom: 24,
    },
    title: {
        fontSize: 15,
        fontWeight: '600',
    },
    subtitle: {
        fontSize: 13,
        marginTop: 2,
    },
    time: {
        fontSize: 12,
        marginTop: 2,
    },
});
