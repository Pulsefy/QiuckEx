import React from "react";
import {
    ActivityIndicator,
    Modal,
    Pressable,
    StyleSheet,
    Text,
    TextInput,
    View,
} from "react-native";
import { useTheme } from "../../src/theme/ThemeContext";

interface PinAuthModalProps {
  visible: boolean;
  title: string;
  description: string;
  pin: string;
  errorMessage: string | null;
  submitting: boolean;
  onPinChange: (value: string) => void;
  onSubmit: () => void;
  onCancel: () => void;
}

export function PinAuthModal({
  visible,
  title,
  description,
  pin,
  errorMessage,
  submitting,
  onPinChange,
  onSubmit,
  onCancel,
}: PinAuthModalProps) {
  const { theme } = useTheme();

  return (
    <Modal
      visible={visible}
      transparent
      animationType="fade"
      onRequestClose={onCancel}
    >
      <View style={[styles.backdrop, { backgroundColor: theme.overlayBg }]}>
        <View style={[styles.card, { backgroundColor: theme.surfaceElevated }]}>
          <Text style={[styles.title, { color: theme.textPrimary }]}>{title}</Text>
          <Text style={[styles.description, { color: theme.textSecondary }]}>{description}</Text>

          <TextInput
            value={pin}
            onChangeText={onPinChange}
            style={[styles.input, { borderColor: theme.inputBorder, color: theme.inputText }]}
            maxLength={6}
            keyboardType="number-pad"
            secureTextEntry
            placeholder="Enter 4-6 digit PIN"
            placeholderTextColor={theme.inputPlaceholder}
            autoFocus
          />

          {errorMessage ? (
            <Text style={[styles.errorText, { color: theme.status.error }]}>{errorMessage}</Text>
          ) : null}

          <View style={styles.actions}>
            <Pressable
              style={[styles.cancelBtn, { backgroundColor: theme.surface }]}
              onPress={onCancel}
              disabled={submitting}
            >
              <Text style={[styles.cancelText, { color: theme.textSecondary }]}>Cancel</Text>
            </Pressable>
            <Pressable
              style={[styles.confirmBtn, { backgroundColor: theme.buttonPrimaryBg }]}
              onPress={onSubmit}
              disabled={submitting}
            >
              {submitting ? (
                <ActivityIndicator color={theme.buttonPrimaryText} />
              ) : (
                <Text style={[styles.confirmText, { color: theme.buttonPrimaryText }]}>Verify PIN</Text>
              )}
            </Pressable>
          </View>
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  backdrop: {
    flex: 1,
    justifyContent: "center",
    padding: 24,
  },
  card: {
    borderRadius: 20,
    padding: 24,
  },
  title: {
    fontSize: 22,
    fontWeight: "700",
    marginBottom: 8,
  },
  description: {
    fontSize: 14,
    lineHeight: 20,
    marginBottom: 20,
  },
  input: {
    borderWidth: 1,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 12,
    fontSize: 16,
    marginBottom: 10,
  },
  errorText: {
    fontSize: 13,
    marginBottom: 8,
  },
  actions: {
    flexDirection: "row",
    justifyContent: "flex-end",
    gap: 10,
    marginTop: 4,
  },
  cancelBtn: {
    borderRadius: 10,
    paddingVertical: 10,
    paddingHorizontal: 14,
  },
  cancelText: {
    fontWeight: "600",
  },
  confirmBtn: {
    borderRadius: 10,
    paddingVertical: 10,
    paddingHorizontal: 16,
    minWidth: 100,
    alignItems: "center",
  },
  confirmText: {
    fontWeight: "700",
  },
});
