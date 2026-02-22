import React, { useMemo } from "react";
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Share,
  useColorScheme,
  Alert,
} from "react-native";
import QRCode from "react-native-qrcode-svg";
import * as Clipboard from "expo-clipboard";

// TODO: Replace this with real auth hook
const useUser = () => {
  return {
    username: "amarjeet", // mock for now
  };
};

export default function QuickReceiveScreen() {
  const { username } = useUser();
  const colorScheme = useColorScheme();
  const isDark = colorScheme === "dark";

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
    <View style={[styles.container, isDark && styles.darkContainer]}>
      <Text style={[styles.title, isDark && styles.darkText]}>
        Quick Receive
      </Text>

      {!username ? (
        <View style={styles.emptyContainer}>
          <Text style={[styles.warning, isDark && styles.darkText]}>
            No username found.
          </Text>
          <Text style={[styles.subText, isDark && styles.darkText]}>
            Claim one to start receiving payments.
          </Text>
        </View>
      ) : (
        <>
          <Text style={[styles.username, isDark && styles.darkText]}>
            @{username}
          </Text>

          <View style={styles.qrWrapper}>
            <QRCode
              value={receiveLink!}
              size={220}
              backgroundColor="#ffffff"
              color="#000000"
            />
          </View>

          <TouchableOpacity
            style={styles.primaryButton}
            onPress={handleCopy}
          >
            <Text style={styles.buttonText}>Copy Link</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.secondaryButton}
            onPress={handleShare}
          >
            <Text style={styles.buttonText}>Share</Text>
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
    backgroundColor: "#ffffff",
  },
  darkContainer: {
    backgroundColor: "#121212",
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
  darkText: {
    color: "#ffffff",
  },
  qrWrapper: {
    padding: 16,
    backgroundColor: "#ffffff",
    borderRadius: 16,
    marginBottom: 30,
  },
  primaryButton: {
    width: "100%",
    backgroundColor: "#2563EB",
    padding: 14,
    borderRadius: 12,
    alignItems: "center",
    marginBottom: 12,
  },
  secondaryButton: {
    width: "100%",
    backgroundColor: "#10B981",
    padding: 14,
    borderRadius: 12,
    alignItems: "center",
  },
  buttonText: {
    color: "#ffffff",
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