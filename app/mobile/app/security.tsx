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

export default function SecurityScreen() {
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
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.title}>Security</Text>
        <Text style={styles.subtitle}>
          Protect sensitive flows with biometrics and a fallback PIN.
        </Text>

        <View style={styles.card}>
          <View style={styles.row}>
            <View style={styles.rowTextWrap}>
              <Text style={styles.rowTitle}>Enable Biometric Lock</Text>
              <Text style={styles.rowBody}>
                Prompt on app open and before critical transactions.
              </Text>
            </View>
            <Switch
              value={settings.biometricLockEnabled}
              onValueChange={onToggle}
              disabled={!isBiometricAvailable}
            />
          </View>

          <View style={styles.divider} />

          <Text style={styles.supportText}>
            {isBiometricAvailable
              ? "Biometric hardware is available on this device."
              : "Biometrics unavailable. You can still set fallback PIN now and enable biometrics when available."}
          </Text>
        </View>

        <View style={styles.card}>
          <Text style={styles.rowTitle}>
            {hasPinConfigured ? "Change Fallback PIN" : "Set Fallback PIN"}
          </Text>
          <Text style={styles.rowBody}>
            PIN is stored as a hash in secure storage and used when biometrics
            fail or are unavailable.
          </Text>

          <TextInput
            style={styles.input}
            placeholder="Enter 4-6 digit PIN"
            placeholderTextColor="#9CA3AF"
            value={pin}
            onChangeText={(value) => setPin(value.replace(/[^0-9]/g, ""))}
            secureTextEntry
            keyboardType="number-pad"
            maxLength={6}
          />
          <TextInput
            style={styles.input}
            placeholder="Confirm PIN"
            placeholderTextColor="#9CA3AF"
            value={confirmPin}
            onChangeText={(value) =>
              setConfirmPin(value.replace(/[^0-9]/g, ""))
            }
            secureTextEntry
            keyboardType="number-pad"
            maxLength={6}
          />

          <Pressable
            style={styles.saveBtn}
            onPress={submitPin}
            disabled={savingPin}
          >
            <Text style={styles.saveBtnText}>
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
    backgroundColor: "#FFFFFF",
  },
  content: {
    flex: 1,
    padding: 24,
  },
  title: {
    fontSize: 34,
    fontWeight: "800",
    color: "#111827",
  },
  subtitle: {
    marginTop: 8,
    fontSize: 16,
    color: "#6B7280",
    marginBottom: 26,
    lineHeight: 22,
  },
  card: {
    backgroundColor: "#F9FAFB",
    borderRadius: 16,
    padding: 16,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: "#E5E7EB",
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
    color: "#111827",
    marginBottom: 4,
  },
  rowBody: {
    color: "#6B7280",
    fontSize: 14,
    lineHeight: 20,
  },
  supportText: {
    color: "#4B5563",
    fontSize: 13,
  },
  divider: {
    height: 1,
    backgroundColor: "#E5E7EB",
    marginVertical: 14,
  },
  input: {
    backgroundColor: "#fff",
    borderRadius: 10,
    borderWidth: 1,
    borderColor: "#D1D5DB",
    paddingHorizontal: 14,
    paddingVertical: 12,
    marginTop: 12,
    fontSize: 15,
  },
  saveBtn: {
    marginTop: 14,
    backgroundColor: "#111827",
    borderRadius: 12,
    alignItems: "center",
    paddingVertical: 14,
  },
  saveBtnText: {
    color: "#fff",
    fontWeight: "700",
    fontSize: 16,
  },
});
