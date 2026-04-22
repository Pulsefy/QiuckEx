import React, { useState } from "react";
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Alert } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { useRouter } from "expo-router";
import { saveContact } from "../services/contacts";
import { useTheme } from "../src/theme/ThemeContext";

export default function AddContactScreen() {
  const { theme } = useTheme();
  const [nickname, setNickname] = useState("");
  const [address, setAddress] = useState("");
  const [saving, setSaving] = useState(false);
  const router = useRouter();

  async function handleSave() {
    if (!address.trim()) {
      Alert.alert("Address is required");
      return;
    }
    setSaving(true);
    try {
      await saveContact({
        address: address.trim(),
        nickname: nickname.trim(),
      } as any);
      router.replace("/contacts");
    } catch (e) {
      Alert.alert("Failed to save contact");
    } finally {
      setSaving(false);
    }
  }

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <Text style={[styles.title, { color: theme.textPrimary }]}>Add Contact</Text>
      <TextInput
        style={[styles.input, { borderColor: theme.inputBorder, backgroundColor: theme.inputBg, color: theme.inputText }]}
        placeholder="Nickname (optional)"
        placeholderTextColor={theme.inputPlaceholder}
        value={nickname}
        onChangeText={setNickname}
      />
      <TextInput
        style={[styles.input, { borderColor: theme.inputBorder, backgroundColor: theme.inputBg, color: theme.inputText }]}
        placeholder="Address (required)"
        placeholderTextColor={theme.inputPlaceholder}
        value={address}
        onChangeText={setAddress}
        autoCapitalize="none"
        autoCorrect={false}
      />
      <TouchableOpacity
        style={[styles.saveButton, { backgroundColor: theme.primary }, saving && { opacity: 0.6 }]}
        onPress={handleSave}
        disabled={saving}
      >
        <Text style={[styles.saveButtonText, { color: theme.primaryForeground }]}>{saving ? "Saving..." : "Save Contact"}</Text>
      </TouchableOpacity>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16 },
  title: { fontSize: 28, fontWeight: "bold", marginBottom: 16, alignSelf: "center" },
  input: { borderWidth: 1, borderRadius: 8, padding: 12, marginBottom: 16, fontSize: 16 },
  saveButton: { padding: 14, borderRadius: 8, alignItems: "center" },
  saveButtonText: { fontWeight: "bold", fontSize: 16 },
});
