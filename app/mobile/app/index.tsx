import { Link } from 'expo-router';
import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

export default function HomeScreen() {
    return (
        <SafeAreaView style={styles.container}>
            <View style={styles.content}>
                <Text style={styles.title}>QuickEx</Text>
                <Text style={styles.subtitle}>
                    Fast, privacy-focused payment link platform built on Stellar.
                </Text>

                <View style={styles.card}>
                    <Text style={styles.cardTitle}>Instant Payments</Text>
                    <Text style={styles.cardText}>
                        Receive USDC, XLM, or any Stellar asset directly to your self-custody wallet.
                    </Text>
                </View>

                <Link href="/wallet-connect" asChild>
                    <TouchableOpacity style={styles.button}>
                        <Text style={styles.buttonText}>Connect Wallet</Text>
                    </TouchableOpacity>
                </Link>

                <Link href="/transactions" asChild>
                    <TouchableOpacity style={styles.secondaryButton}>
                        <Text style={styles.secondaryButtonText}>Transaction History</Text>
                    </TouchableOpacity>
                </Link>
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
        justifyContent: 'center',
        alignItems: 'center',
    },
    title: {
        fontSize: 42,
        fontWeight: 'bold',
        color: '#000',
        marginBottom: 8,
    },
    subtitle: {
        fontSize: 18,
        color: '#666',
        textAlign: 'center',
        marginBottom: 40,
    },
    card: {
        width: '100%',
        padding: 20,
        borderRadius: 12,
        backgroundColor: '#f5f5f5',
        marginBottom: 30,
    },
    cardTitle: {
        fontSize: 20,
        fontWeight: '600',
        color: '#333',
        marginBottom: 8,
    },
    cardText: {
        fontSize: 16,
        color: '#555',
        lineHeight: 22,
    },
    button: {
        backgroundColor: '#000',
        paddingVertical: 16,
        paddingHorizontal: 32,
        borderRadius: 8,
        width: '100%',
        alignItems: 'center',
    },
    buttonText: {
        color: '#fff',
        fontSize: 18,
        fontWeight: 'bold',
    },
    secondaryButton: {
        marginTop: 12,
        paddingVertical: 16,
        paddingHorizontal: 32,
        borderRadius: 8,
        width: '100%',
        alignItems: 'center',
        borderWidth: 1,
        borderColor: '#000',
    },
    secondaryButtonText: {
        color: '#000',
        fontSize: 18,
        fontWeight: '600',
    },
});
