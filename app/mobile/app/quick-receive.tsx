import React, { useMemo } from "react";
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Share,
  Alert,
} from "react-native";
import QRCode from "react-native-qrcode-svg";
import * as Clipboard from "expo-clipboard";
import { useRouter } from "expo-router";
import { useTheme } from "../src/theme/ThemeContext";
import { useWallet } from "../hooks/useWallet";

export default function QuickReceiveScreen() {
  const { wallet } = useWallet();
  const { theme } = useTheme();
  const router = useRouter();

  const isConnected = wallet.connected && Boolean(wallet.publicKey);
  const accountIdentifier = wallet.publicKey;

  const truncatedAddress = useMemo(() => {
    if (!accountIdentifier) return "";
    if (accountIdentifier.length <= 12) return accountIdentifier;
    return `${accountIdentifier.slice(0, 6)}...${accountIdentifier.slice(-6)}`;
  }, [accountIdentifier]);

  const receiveLink = useMemo(() => {
    if (!accountIdentifier) return null;
    return `https://quickex.to/${accountIdentifier}`;
  }, [accountIdentifier]);

  const handleCopyLink = async () => {
    if (!receiveLink) return;
    await Clipboard.setStringAsync(receiveLink);
    Alert.alert("Copied", "Link copied to clipboard");
  };

  const handleCopyAddress = async () => {
    if (!accountIdentifier) return;
    await Clipboard.setStringAsync(accountIdentifier);
    Alert.alert("Copied", "Public key copied to clipboard");
  };

  const handleShare = async () => {
    if (!receiveLink) return;

    await Share.share({
      message: `Send me payment via QuickEx:\n${receiveLink}`,
    });
  };

  const handleConnectWallet = () => {
    router.push("/wallet-connect");
  };

  return (
    <View style={[styles.container, { backgroundColor: theme.background }]}>
      <Text
        style={[styles.title, { color: theme.textPrimary }]}
        accessibilityRole="header"
      >
        Quick Receive
      </Text>

      {!isConnected ? (
        <View
          style={styles.emptyContainer}
          accessibilityLabel="No wallet connected. Connect your Stellar wallet to display your QR code and start receiving payments."
        >
          <Text
            style={[styles.warning, { color: theme.textPrimary }]}
            accessibilityElementsHidden={true}
            importantForAccessibility="no"
          >
            No wallet connected
          </Text>
          <Text
            style={[styles.subText, { color: theme.textSecondary }]}
            accessibilityElementsHidden={true}
            importantForAccessibility="no"
          >
            Connect your Stellar wallet to display your QR code and start receiving payments.
          </Text>

          <TouchableOpacity
            style={[styles.primaryButton, { backgroundColor: theme.status.info, marginTop: 24 }]}
            onPress={handleConnectWallet}
            accessibilityLabel="Connect your Stellar wallet to receive payments."
            accessibilityRole="button"
            accessibilityHint="Navigates to wallet connection screen."
          >
            <Text
              style={[styles.buttonText, { color: theme.buttonPrimaryText }]}
              accessibilityElementsHidden={true}
              importantForAccessibility="no"
            >
              Connect Wallet
            </Text>
          </TouchableOpacity>
        </View>
      ) : (
        <>
          <View
            style={[styles.badgeContainer, { backgroundColor: theme.chipBg }]}
            accessibilityLabel={`Wallet connected. ${wallet.walletType ? wallet.walletType.toUpperCase() : "Unknown wallet"} on ${wallet.network.toUpperCase()} network.`}
          >
            {wallet.walletType ? (
              <Text
                style={[styles.badgeText, { color: theme.chipText }]}
                accessibilityElementsHidden={true}
                importantForAccessibility="no"
              >
                {wallet.walletType.toUpperCase()} • {wallet.network.toUpperCase()}
              </Text>
            ) : null}
          </View>

          <TouchableOpacity
            onPress={handleCopyAddress}
            activeOpacity={0.7}
            accessibilityLabel={`Public key ${truncatedAddress}. Tap to copy full Stellar address to clipboard.`}
            accessibilityHint={`Copies full public key: ${accountIdentifier}`}
            accessibilityRole="button"
            hitSlop={{ top: 8, bottom: 8, left: 16, right: 16 }}
          >
            <Text
              style={[styles.username, { color: theme.textPrimary }]}
              accessibilityElementsHidden={true}
              importantForAccessibility="no"
            >
              {truncatedAddress}
            </Text>
          </TouchableOpacity>

          <View
            style={[styles.qrWrapper, { backgroundColor: theme.qrBackground }]}
            accessibilityLabel={`QuickEx receive QR code. Encoded value: ${receiveLink}. Scan this code with a QuickEx wallet to send you payment.`}
          >
            <QRCode
              value={receiveLink!}
              size={220}
              backgroundColor={theme.qrBackground}
              color={theme.qrForeground}
            />
          </View>

          <TouchableOpacity
            style={[styles.primaryButton, { backgroundColor: theme.status.info }]}
            onPress={handleCopyLink}
            accessibilityLabel={`Copy QuickEx receive link: ${receiveLink}. Double tap to copy to clipboard.`}
            accessibilityRole="button"
          >
            <Text
              style={[styles.buttonText, { color: theme.buttonPrimaryText }]}
              accessibilityElementsHidden={true}
              importantForAccessibility="no"
            >Copy Link</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.secondaryButton, { backgroundColor: theme.chipBg, marginBottom: 12 }]}
            onPress={handleCopyAddress}
            accessibilityLabel={`Copy full Stellar public key address: ${accountIdentifier}. Double tap to copy to clipboard.`}
            accessibilityRole="button"
          >
            <Text
              style={[styles.buttonText, { color: theme.textPrimary }]}
              accessibilityElementsHidden={true}
              importantForAccessibility="no"
            >Copy Address</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.secondaryButton, { backgroundColor: theme.status.success }]}
            onPress={handleShare}
            accessibilityLabel={`Share my QuickEx receive payment link via system share sheet. Link: ${receiveLink}.`}
            accessibilityRole="button"
          >
            <Text
              style={[styles.buttonText, { color: theme.buttonPrimaryText }]}
              accessibilityElementsHidden={true}
              importantForAccessibility="no"
            >Share</Text>
          </TouchableOpacity>
        </>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 24,
    alignItems: "center",
    justifyContent: "center",
  },
  title: {
    fontSize: 22,
    fontWeight: "600",
    marginBottom: 24,
  },
  username: {
    fontSize: 18,
    fontWeight: "bold",
    marginBottom: 20,
    fontFamily: "monospace",
  },
  badgeContainer: {
    paddingHorizontal: 12,
    paddingVertical: 4,
    borderRadius: 12,
    marginBottom: 8,
  },
  badgeText: {
    fontSize: 12,
    fontWeight: "600",
    letterSpacing: 0.5,
  },
  qrWrapper: {
    padding: 16,
    borderRadius: 16,
    marginBottom: 30,
  },
  primaryButton: {
    width: "100%",
    padding: 14,
    borderRadius: 12,
    alignItems: "center",
    marginBottom: 12,
    minHeight: 48,
    justifyContent: "center",
  },
  secondaryButton: {
    width: "100%",
    padding: 14,
    borderRadius: 12,
    alignItems: "center",
    minHeight: 48,
    justifyContent: "center",
  },
  buttonText: {
    fontWeight: "600",
  },
  emptyContainer: {
    alignItems: "center",
    width: "100%",
    paddingHorizontal: 16,
  },
  warning: {
    fontSize: 18,
    fontWeight: "600",
    marginBottom: 8,
    textAlign: "center",
  },
  subText: {
    fontSize: 14,
    lineHeight: 20,
    textAlign: "center",
    opacity: 0.8,
  },
});