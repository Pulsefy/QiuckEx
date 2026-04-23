import React, { useState } from "react";
import {
    Alert,
    Pressable,
    StyleSheet,
    Switch,
    Text,
    TextInput,
    View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

import { useSecurity } from "@/hooks/use-security";
import { useTheme } from "../src/theme/ThemeContext";

export default function SecurityScreen() {
  const { theme } = useTheme();
  const {
    settings,
    isBiometricAvailable,
    hasPinConfigured,
    setBiometricLockEnabled,
    savePin,
  } = useSecurity();

  const [pin, setPin] = useState("");
  const [confirmPin, setConfirmPin] = useState("");
  const [savingPin, setSavingPin] = useState(false);

  const submitPin = async () => {
    if (pin !== confirmPin) {
      Alert.alert("PIN mismatch", "PIN and confirmation must match.");
      return;
    }

    setSavingPin(true);
    const result = await savePin(pin);
    setSavingPin(false);

    if (!result.ok) {
      Alert.alert(
        "Invalid PIN",
        result.error ?? "Please check the PIN format.",
      );
      return;
    }

    setPin("");
    setConfirmPin("");
    Alert.alert("PIN saved", "Fallback PIN is now configured securely.");
  };

  const onToggle = async (enabled: boolean) => {
    const result = await setBiometricLockEnabled(enabled);
    if (!result.ok) {
      Alert.alert(
        "Security setup required",
        result.error ?? "Could not update setting.",
      );
      return;
    }

    Alert.alert(
      enabled ? "Biometric lock enabled" : "Biometric lock disabled",
      enabled
        ? "QuickEx will require biometrics or fallback PIN when opening and before sensitive actions."
        : "Biometric lock has been turned off.",
    );
  };

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <View style={styles.content}>
        <Text style={[styles.title, { color: theme.textPrimary }]}>Security</Text>
        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
          Protect sensitive flows with biometrics and a fallback PIN.
        </Text>

        <View style={[styles.card, { backgroundColor: theme.surface, borderColor: theme.border }]}>
          <View style={styles.row}>
            <View style={styles.rowTextWrap}>
              <Text style={[styles.rowTitle, { color: theme.textPrimary }]}>Enable Biometric Lock</Text>
              <Text style={[styles.rowBody, { color: theme.textSecondary }]}>
                Prompt on app open and before critical transactions.
              </Text>
            </View>
            <Switch
              value={settings.biometricLockEnabled}
              onValueChange={onToggle}
              disabled={!isBiometricAvailable}
            />
          </View>

          <View style={[styles.divider, { backgroundColor: theme.border }]} />

          <Text style={[styles.supportText, { color: theme.textSecondary }]}>
            {isBiometricAvailable
              ? "Biometric hardware is available on this device."
              : "Biometrics unavailable. You can still set fallback PIN now and enable biometrics when available."}
          </Text>
        </View>

        <View style={[styles.card, { backgroundColor: theme.surface, borderColor: theme.border }]}>
          <Text style={[styles.rowTitle, { color: theme.textPrimary }]}>
            {hasPinConfigured ? "Change Fallback PIN" : "Set Fallback PIN"}
          </Text>
          <Text style={[styles.rowBody, { color: theme.textSecondary }]}>
            PIN is stored as a hash in secure storage and used when biometrics
            fail or are unavailable.
          </Text>

          <TextInput
            style={[styles.input, { backgroundColor: theme.surfaceElevated, borderColor: theme.inputBorder, color: theme.inputText }]}
            placeholder="Enter 4-6 digit PIN"
            placeholderTextColor={theme.inputPlaceholder}
            value={pin}
            onChangeText={(value) => setPin(value.replace(/[^0-9]/g, ""))}
            secureTextEntry
            keyboardType="number-pad"
            maxLength={6}
          />
          <TextInput
            style={[styles.input, { backgroundColor: theme.surfaceElevated, borderColor: theme.inputBorder, color: theme.inputText }]}
            placeholder="Confirm PIN"
            placeholderTextColor={theme.inputPlaceholder}
            value={confirmPin}
            onChangeText={(value) =>
              setConfirmPin(value.replace(/[^0-9]/g, ""))
            }
            secureTextEntry
            keyboardType="number-pad"
            maxLength={6}
          />

          <Pressable
            style={[styles.saveBtn, { backgroundColor: theme.buttonPrimaryBg }]}
            onPress={submitPin}
            disabled={savingPin}
          >
            <Text style={[styles.saveBtnText, { color: theme.buttonPrimaryText }]}>
              {savingPin ? "Saving..." : "Save PIN"}
            </Text>
          </Pressable>
        </View>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  content: {
    flex: 1,
    padding: 24,
  },
  title: {
    fontSize: 34,
    fontWeight: "800",
  },
  subtitle: {
    marginTop: 8,
    fontSize: 16,
    marginBottom: 26,
    lineHeight: 22,
  },
  card: {
    borderRadius: 16,
    padding: 16,
    marginBottom: 16,
    borderWidth: 1,
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 16,
  },
  rowTextWrap: {
    flex: 1,
  },
  rowTitle: {
    fontSize: 17,
    fontWeight: "700",
    marginBottom: 4,
  },
  rowBody: {
    fontSize: 14,
    lineHeight: 20,
  },
  supportText: {
    fontSize: 13,
  },
  divider: {
    height: 1,
    marginVertical: 14,
  },
  input: {
    borderRadius: 10,
    borderWidth: 1,
    paddingHorizontal: 14,
    paddingVertical: 12,
    marginTop: 12,
    fontSize: 15,
  },
  saveBtn: {
    marginTop: 14,
    borderRadius: 12,
    alignItems: "center",
    paddingVertical: 14,
  },
  saveBtnText: {
    fontWeight: "700",
    fontSize: 16,
  },
});
