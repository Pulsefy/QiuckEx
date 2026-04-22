import React from "react";
import {
  Modal,
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
} from "react-native";
import QRCode from "react-native-qrcode-svg";
import { useTheme } from "../src/theme/ThemeContext";

interface QRPreviewModalProps {
  visible: boolean;
  value: string;
  onClose: () => void;
}

export function QRPreviewModal({ visible, value, onClose }: QRPreviewModalProps) {
  const { theme } = useTheme();

  return (
    <Modal
      visible={visible}
      transparent={true}
      animationType="fade"
      onRequestClose={onClose}
    >
      <SafeAreaView style={[styles.overlay, { backgroundColor: theme.overlayBg }]}>
        <View style={styles.content}>
          <Text style={styles.title}>
            Scan to Pay
          </Text>

          {/* QR codes must always be black-on-white for scanner readability */}
          <View style={[styles.qrWrapper, { backgroundColor: theme.qrBackground }]}>
            <QRCode
              value={value}
              size={280}
              backgroundColor={theme.qrBackground}
              color={theme.qrForeground}
            />
          </View>

          <TouchableOpacity
            style={[styles.closeButton, { backgroundColor: theme.surfaceElevated }]}
            onPress={onClose}
          >
            <Text style={[styles.closeButtonText, { color: theme.textPrimary }]}>Close</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    </Modal>
  );
}

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    justifyContent: "center",
  },
  content: {
    flex: 1,
    padding: 24,
    justifyContent: "center",
    alignItems: "center",
  },
  title: {
    fontSize: 28,
    fontWeight: "bold",
    marginBottom: 40,
    color: "#ffffff", // Intentional: always white over dark overlay
  },
  qrWrapper: {
    padding: 24,
    borderRadius: 24,
    marginBottom: 60,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 10 },
    shadowOpacity: 0.3,
    shadowRadius: 20,
    elevation: 10,
  },
  closeButton: {
    width: "100%",
    paddingVertical: 18,
    borderRadius: 16,
    alignItems: "center",
  },
  closeButtonText: {
    fontSize: 18,
    fontWeight: "600",
  },
});
