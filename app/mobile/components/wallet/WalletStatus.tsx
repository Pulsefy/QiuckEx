import React from "react";
import { StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { SUPPORTED_WALLETS } from "../../hooks/useWalletContext";
import { useTheme } from "../../src/theme/ThemeContext";
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
  const { theme } = useTheme();

  const walletLabel = wallet.walletType
    ? (SUPPORTED_WALLETS.find((w) => w.type === wallet.walletType)?.label ??
      wallet.walletType)
    : null;

  return (
    <View style={[styles.container, { backgroundColor: theme.surface }]}>
      <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
        Wallet Status
      </Text>

      <View style={styles.row}>
        <Text style={[styles.label, { color: theme.textPrimary }]}>
          Network:
        </Text>
        <TouchableOpacity
          style={[
            styles.networkBadge,
            {
              backgroundColor:
                wallet.network === "mainnet"
                  ? theme.networkMainnet
                  : theme.networkTestnet,
            },
          ]}
          onPress={onToggleNetwork}
        >
          <Text style={[styles.networkText, { color: theme.qrBackground }]}>
            {wallet.network.toUpperCase()}
          </Text>
        </TouchableOpacity>
      </View>

      <View style={styles.row}>
        <Text style={[styles.label, { color: theme.textPrimary }]}>
          Connection:
        </Text>
        <Text
          style={{
            color: wallet.connected ? theme.status.success : theme.status.error,
            fontWeight: "600",
          }}
        >
          {wallet.connected ? "Connected" : "Not Connected"}
        </Text>
      </View>

      {wallet.connected && walletLabel ? (
        <View style={styles.row}>
          <Text style={[styles.label, { color: theme.textPrimary }]}>
            Wallet:
          </Text>
          <Text style={{ color: theme.textSecondary, fontWeight: "600" }}>
            {walletLabel}
          </Text>
        </View>
      ) : null}

      {wallet.connected && (
        <Text style={[styles.address, { color: theme.textSecondary }]}>
          {wallet.publicKey}
        </Text>
      )}

      {wallet.error ? (
        <Text style={[styles.errorText, { color: theme.status.error }]}>
          {wallet.error.message}
        </Text>
      ) : null}

      {!wallet.connected ? (
        <TouchableOpacity
          style={[
            styles.connectBtn,
            { backgroundColor: theme.buttonPrimaryBg },
          ]}
          onPress={onConnect}
        >
          <Text style={[styles.btnText, { color: theme.buttonPrimaryText }]}>
            Connect Wallet
          </Text>
        </TouchableOpacity>
      ) : (
        <TouchableOpacity
          style={[
            styles.disconnectBtn,
            { backgroundColor: theme.buttonDangerBg },
          ]}
          onPress={onDisconnect}
        >
          <Text style={[styles.btnText, { color: theme.buttonDangerText }]}>
            Disconnect
          </Text>
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
    fontWeight: "600",
  },
  address: {
    fontSize: 12,
    marginBottom: 12,
  },
  errorText: {
    fontSize: 13,
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
