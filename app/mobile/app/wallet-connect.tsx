import { useRouter } from 'expo-router';
import React, { useState } from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

type Network = "testnet" | "mainnet";

export default function WalletConnectScreen() {
    const router = useRouter();

    const [connected, setConnected] = useState(false);
    const [network, setNetwork] = useState<Network>("testnet");
    const [publicKey, setPublicKey] = useState<string | null>(null);

    const handleConnect = () => {
        // Mock connection (replace later with real wallet integration)
        setConnected(true);
        setPublicKey("GABCD1234MOCKPUBLICKEY5678XYZ");
    };

    const handleDisconnect = () => {
        setConnected(false);
        setPublicKey(null);
    };

    const toggleNetwork = () => {
        setNetwork(prev => prev === "testnet" ? "mainnet" : "testnet");
    };

    return (
        <SafeAreaView style={styles.container}>
            <View style={styles.content}>
                <Text style={styles.title}>Wallet Connection</Text>
                <Text style={styles.subtitle}>
                    Securely connect your Stellar wallet to manage your payments.
                </Text>

                {/* Network Indicator */}
                <View style={styles.row}>
                    <Text style={styles.label}>Network:</Text>
                    <TouchableOpacity
                        style={[
                            styles.networkBadge,
                            network === "mainnet"
                                ? styles.mainnet
                                : styles.testnet
                        ]}
                        onPress={toggleNetwork}
                    >
                        <Text style={styles.networkText}>
                            {network.toUpperCase()}
                        </Text>
                    </TouchableOpacity>
                </View>

                {/* Connection Status */}
                <View style={styles.row}>
                    <Text style={styles.label}>Status:</Text>
                    <Text style={connected ? styles.connected : styles.disconnected}>
                        {connected ? "Connected" : "Not Connected"}
                    </Text>
                </View>

                {/* Public Key */}
                {connected && publicKey && (
                    <Text style={styles.address}>
                        {publicKey}
                    </Text>
                )}

                {/* Connect / Disconnect Button */}
                {!connected ? (
                    <TouchableOpacity
                        style={styles.connectButton}
                        onPress={handleConnect}
                    >
                        <Text style={styles.buttonText}>Connect Wallet</Text>
                    </TouchableOpacity>
                ) : (
                    <TouchableOpacity
                        style={styles.disconnectButton}
                        onPress={handleDisconnect}
                    >
                        <Text style={styles.buttonText}>Disconnect</Text>
                    </TouchableOpacity>
                )}

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
    },
    title: {
        fontSize: 32,
        fontWeight: 'bold',
        marginTop: 40,
        marginBottom: 12,
    },
    subtitle: {
        fontSize: 16,
        color: '#666',
        marginBottom: 40,
    },
    row: {
        flexDirection: "row",
        justifyContent: "space-between",
        alignItems: "center",
        marginBottom: 16,
    },
    label: {
        fontSize: 16,
        fontWeight: "600",
    },
    networkBadge: {
        paddingHorizontal: 12,
        paddingVertical: 6,
        borderRadius: 8,
    },
    mainnet: {
        backgroundColor: "#10B981",
    },
    testnet: {
        backgroundColor: "#F59E0B",
    },
    networkText: {
        color: "#fff",
        fontWeight: "600",
    },
    connected: {
        color: "#10B981",
        fontWeight: "600",
    },
    disconnected: {
        color: "#EF4444",
        fontWeight: "600",
    },
    address: {
        fontSize: 12,
        marginBottom: 20,
    },
    connectButton: {
        backgroundColor: "#000",
        padding: 16,
        borderRadius: 8,
        alignItems: "center",
        marginBottom: 12,
    },
    disconnectButton: {
        backgroundColor: "#EF4444",
        padding: 16,
        borderRadius: 8,
        alignItems: "center",
        marginBottom: 12,
    },
    buttonText: {
        color: "#fff",
        fontWeight: "600",
        fontSize: 16,
    },
    backButton: {
        marginTop: 30,
        alignItems: "center",
    },
    backButtonText: {
        color: "#666",
        fontSize: 16,
    },
});