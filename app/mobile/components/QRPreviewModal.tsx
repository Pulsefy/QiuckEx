import React from "react";
import {
  Modal,
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  useColorScheme,
  SafeAreaView,
} from "react-native";
import QRCode from "react-native-qrcode-svg";

interface QRPreviewModalProps {
  visible: boolean;
  value: string;
  onClose: () => void;
}

export function QRPreviewModal({ visible, value, onClose }: QRPreviewModalProps) {
  const colorScheme = useColorScheme();
  const isDark = colorScheme === "dark";

  return (
    <Modal
      visible={visible}
      transparent={true}
      animationType="fade"
      onRequestClose={onClose}
    >
      <SafeAreaView style={styles.overlay}>
        <View style={styles.content}>
          <Text style={styles.title}>
            Scan to Pay
          </Text>

          <View style={styles.qrWrapper}>
            <QRCode
              value={value}
              size={280}
              backgroundColor="#ffffff"
              color="#000000"
            />
          </View>

          <TouchableOpacity style={styles.closeButton} onPress={onClose}>
            <Text style={styles.closeButtonText}>Close</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    </Modal>
  );
}

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: "rgba(0, 0, 0, 0.9)",
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
    color: "#ffffff",
  },
  qrWrapper: {
    padding: 24,
    backgroundColor: "#ffffff",
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
    backgroundColor: "#ffffff",
    borderRadius: 16,
    alignItems: "center",
  },
  closeButtonText: {
    fontSize: 18,
    fontWeight: "600",
    color: "#000000",
  },
});
