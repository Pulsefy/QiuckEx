import React from "react";
import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { WalletState } from "../../types/wallet";

interface Props {
  wallet: WalletState;
  onConnect: () => void;
  onDisconnect: () => void;
  onToggleNetwork: () => void;
}

export default function WalletStatus({
  wallet,
  onConnect,
  onDisconnect,
  onToggleNetwork,
}: Props) {
  return (
    <View style={styles.container}>
      <Text style={styles.sectionTitle}>Wallet Status</Text>

      <View style={styles.row}>
        <Text style={styles.label}>Network:</Text>
        <TouchableOpacity
          style={[
            styles.networkBadge,
            wallet.network === "mainnet"
              ? styles.mainnet
              : styles.testnet,
          ]}
          onPress={onToggleNetwork}
        >
          <Text style={styles.networkText}>
            {wallet.network.toUpperCase()}
          </Text>
        </TouchableOpacity>
      </View>

      <View style={styles.row}>
        <Text style={styles.label}>Connection:</Text>
        <Text style={wallet.connected ? styles.connected : styles.disconnected}>
          {wallet.connected ? "Connected" : "Not Connected"}
        </Text>
      </View>

      {wallet.connected && (
        <Text style={styles.address}>
          {wallet.publicKey}
        </Text>
      )}

      {!wallet.connected ? (
        <TouchableOpacity style={styles.connectBtn} onPress={onConnect}>
          <Text style={styles.btnText}>Connect Wallet</Text>
        </TouchableOpacity>
      ) : (
        <TouchableOpacity style={styles.disconnectBtn} onPress={onDisconnect}>
          <Text style={styles.btnText}>Disconnect</Text>
        </TouchableOpacity>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    width: "100%",
    padding: 20,
    borderRadius: 12,
    backgroundColor: "#f5f5f5",
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: "600",
    marginBottom: 16,
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 12,
  },
  label: {
    fontSize: 16,
    fontWeight: "500",
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
    marginBottom: 12,
  },
  connectBtn: {
    backgroundColor: "#000",
    padding: 14,
    borderRadius: 8,
    alignItems: "center",
  },
  disconnectBtn: {
    backgroundColor: "#EF4444",
    padding: 14,
    borderRadius: 8,
    alignItems: "center",
  },
  btnText: {
    color: "#fff",
    fontWeight: "600",
  },
});