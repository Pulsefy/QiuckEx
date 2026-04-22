import React from "react";
import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { WalletState } from "../../types/wallet";
import { useTheme } from "../../src/theme/ThemeContext";

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
  const { theme } = useTheme();

  return (
    <View style={[styles.container, { backgroundColor: theme.surface }]}>
      <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>Wallet Status</Text>

      <View style={styles.row}>
        <Text style={[styles.label, { color: theme.textPrimary }]}>Network:</Text>
        <TouchableOpacity
          style={[
            styles.networkBadge,
            { backgroundColor: wallet.network === "mainnet" ? theme.networkMainnet : theme.networkTestnet },
          ]}
          onPress={onToggleNetwork}
        >
          <Text style={styles.networkText}>
            {wallet.network.toUpperCase()}
          </Text>
        </TouchableOpacity>
      </View>

      <View style={styles.row}>
        <Text style={[styles.label, { color: theme.textPrimary }]}>Connection:</Text>
        <Text style={{ color: wallet.connected ? theme.status.success : theme.status.error, fontWeight: "600" }}>
          {wallet.connected ? "Connected" : "Not Connected"}
        </Text>
      </View>

      {wallet.connected && (
        <Text style={[styles.address, { color: theme.textSecondary }]}>
          {wallet.publicKey}
        </Text>
      )}

      {!wallet.connected ? (
        <TouchableOpacity style={[styles.connectBtn, { backgroundColor: theme.buttonPrimaryBg }]} onPress={onConnect}>
          <Text style={[styles.btnText, { color: theme.buttonPrimaryText }]}>Connect Wallet</Text>
        </TouchableOpacity>
      ) : (
        <TouchableOpacity style={[styles.disconnectBtn, { backgroundColor: theme.buttonDangerBg }]} onPress={onDisconnect}>
          <Text style={[styles.btnText, { color: theme.buttonDangerText }]}>Disconnect</Text>
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
  networkText: {
    color: "#fff", // Intentional: always white on coloured network badge
    fontWeight: "600",
  },
  address: {
    fontSize: 12,
    marginBottom: 12,
  },
  connectBtn: {
    padding: 14,
    borderRadius: 8,
    alignItems: "center",
  },
  disconnectBtn: {
    padding: 14,
    borderRadius: 8,
    alignItems: "center",
  },
  btnText: {
    fontWeight: "600",
  },
});