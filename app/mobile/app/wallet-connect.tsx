import { useRouter } from 'expo-router';
import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useNetworkStatus } from '../hooks/use-network-status';
import { Ionicons } from '@expo/vector-icons';

export default function WalletConnectScreen() {
    const router = useRouter();
    const { isConnected } = useNetworkStatus();

    return (
        <SafeAreaView style={styles.container}>
            <View style={styles.content}>
                <Text style={styles.title}>Wallet Connection</Text>
                <Text style={styles.subtitle}>
                    Securely connect your Stellar wallet to manage your payments.
                </Text>

                {isConnected === false && (
                    <View style={styles.offlineAdvice}>
                        <Ionicons name="information-circle-outline" size={18} color="#991B1B" />
                        <Text style={styles.offlineAdviceText}>
                            Connection required to link a new wallet.
                        </Text>
                    </View>
                )}

                <View style={styles.placeholder}>
                    <Text style={styles.placeholderText}>
                        [ WalletConnect Placeholder ]
                    </Text>
                    <TouchableOpacity
                        style={[styles.mockButton, isConnected === false && styles.disabledButton]}
                        disabled={isConnected === false}
                    >
                        <Text style={styles.mockButtonText}>Scan QR Code</Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                        style={[styles.mockButton, styles.secondaryButton, isConnected === false && styles.disabledSecondaryButton]}
                        disabled={isConnected === false}
                    >
                        <Text style={[styles.secondaryButtonText, isConnected === false && styles.disabledText]}>Select Wallet</Text>
                    </TouchableOpacity>
                </View>

                <TouchableOpacity
                    style={styles.backButton}
                    onPress={() => router.back()}
                >
                    <Text style={styles.backButtonText}>Go Back</Text>
                </TouchableOpacity>
            </View>
        </SafeAreaView>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#fff',
    },
    content: {
        flex: 1,
        padding: 24,
        alignItems: 'center',
    },
    title: {
        fontSize: 32,
        fontWeight: 'bold',
        color: '#000',
        marginTop: 40,
        marginBottom: 12,
    },
    subtitle: {
        fontSize: 16,
        color: '#666',
        textAlign: 'center',
        marginBottom: 60,
    },
    placeholder: {
        width: '100%',
        padding: 40,
        borderWidth: 2,
        borderColor: '#eee',
        borderStyle: 'dashed',
        borderRadius: 16,
        alignItems: 'center',
        marginBottom: 40,
    },
    placeholderText: {
        fontSize: 18,
        color: '#999',
        fontWeight: '500',
        marginBottom: 30,
    },
    mockButton: {
        backgroundColor: '#007AFF',
        paddingVertical: 12,
        paddingHorizontal: 24,
        borderRadius: 8,
        width: '100%',
        alignItems: 'center',
        marginBottom: 12,
    },
    mockButtonText: {
        color: '#fff',
        fontSize: 16,
        fontWeight: '600',
    },
    secondaryButton: {
        backgroundColor: 'transparent',
        borderWidth: 1,
        borderColor: '#007AFF',
    },
    secondaryButtonText: {
        color: '#007AFF',
        fontSize: 16,
        fontWeight: '600',
    },
    backButton: {
        marginTop: 'auto',
        padding: 16,
    },
    backButtonText: {
        color: '#666',
        fontSize: 16,
    },
    offlineAdvice: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: '#FEF2F2',
        paddingVertical: 8,
        paddingHorizontal: 16,
        borderRadius: 8,
        marginBottom: 20,
        gap: 8,
        borderWidth: 1,
        borderColor: '#FECACA',
    },
    offlineAdviceText: {
        color: '#991B1B',
        fontSize: 13,
        fontWeight: '500',
    },
    disabledButton: {
        backgroundColor: '#E5E7EB',
    },
    disabledSecondaryButton: {
        borderColor: '#E5E7EB',
    },
    disabledText: {
        color: '#9CA3AF',
    },
});
