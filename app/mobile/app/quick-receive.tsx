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
import { useTheme } from "../src/theme/ThemeContext";

// TODO: Replace this with real auth hook
const useUser = () => {
  return {
    username: "amarjeet", // mock for now
  };
};

export default function QuickReceiveScreen() {
  const { username } = useUser();
  const { theme } = useTheme();

  const receiveLink = useMemo(() => {
    if (!username) return null;
    return `https://quickex.to/${username}`;
  }, [username]);

  const handleCopy = async () => {
    if (!receiveLink) return;
    await Clipboard.setStringAsync(receiveLink);
    Alert.alert("Copied", "Link copied to clipboard");
  };

  const handleShare = async () => {
    if (!receiveLink) return;

    await Share.share({
      message: `Send me payment via QuickEx:\n${receiveLink}`,
    });
  };

  return (
    <View style={[styles.container, { backgroundColor: theme.background }]}>
      <Text style={[styles.title, { color: theme.textPrimary }]}>
        Quick Receive
      </Text>

      {!username ? (
        <View style={styles.emptyContainer}>
          <Text style={[styles.warning, { color: theme.textPrimary }]}>
            No username found.
          </Text>
          <Text style={[styles.subText, { color: theme.textSecondary }]}>
            Claim one to start receiving payments.
          </Text>
        </View>
      ) : (
        <>
          <Text style={[styles.username, { color: theme.textPrimary }]}>
            @{username}
          </Text>

          {/* QR codes must always be black-on-white for scanner readability */}
          <View style={[styles.qrWrapper, { backgroundColor: theme.qrBackground }]}>
            <QRCode
              value={receiveLink!}
              size={220}
              backgroundColor={theme.qrBackground}
              color={theme.qrForeground}
            />
          </View>

          <TouchableOpacity
            style={[styles.primaryButton, { backgroundColor: theme.status.info }]}
            onPress={handleCopy}
          >
            <Text style={[styles.buttonText, { color: theme.buttonPrimaryText }]}>Copy Link</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.secondaryButton, { backgroundColor: theme.status.success }]}
            onPress={handleShare}
          >
            <Text style={[styles.buttonText, { color: theme.buttonPrimaryText }]}>Share</Text>
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
    fontSize: 20,
    fontWeight: "bold",
    marginBottom: 20,
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
  },
  secondaryButton: {
    width: "100%",
    padding: 14,
    borderRadius: 12,
    alignItems: "center",
  },
  buttonText: {
    fontWeight: "600",
  },
  emptyContainer: {
    alignItems: "center",
  },
  warning: {
    fontSize: 16,
    fontWeight: "600",
    marginBottom: 6,
  },
  subText: {
    fontSize: 14,
    opacity: 0.7,
  },
});