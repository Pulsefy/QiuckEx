import { useRouter } from 'expo-router';
import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

export default function WalletConnectScreen() {
    const router = useRouter();

    return (
        <SafeAreaView style={styles.container}>
            <View style={styles.content}>
                <Text style={styles.title}>Wallet Connection</Text>
                <Text style={styles.subtitle}>
                    Securely connect your Stellar wallet to manage your payments.
                </Text>

                <View style={styles.placeholder}>
                    <Text style={styles.placeholderText}>
                        [ WalletConnect Placeholder ]
                    </Text>
                    <View style={styles.mockButton}>
                        <Text style={styles.mockButtonText}>Scan QR Code</Text>
                    </View>
                    <View style={[styles.mockButton, styles.secondaryButton]}>
                        <Text style={styles.secondaryButtonText}>Select Wallet</Text>
                    </View>
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
});
