import React, { useEffect, useState } from "react";
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Alert } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { useLocalSearchParams, useRouter } from "expo-router";
import { getContacts, saveContact, updateContact } from "../services/contacts";
import { Contact } from "../types/contact";
import { useTheme } from "../src/theme/ThemeContext";

export default function EditContactScreen() {
  const { theme } = useTheme();
  const { id } = useLocalSearchParams<{ id: string }>();
  const [nickname, setNickname] = useState("");
  const [address, setAddress] = useState("");
  const [contact, setContact] = useState<Contact | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [createdAt, setCreatedAt] = useState<number>(Date.now());
  const router = useRouter();

  useEffect(() => {
    loadContact();
  }, [id]);

  async function loadContact() {
    setLoading(true);
    const contacts = await getContacts();
    const contact = contacts.find((c) => c.id === id);
    if (contact) {
      setContact(contact);
      setNickname(contact.nickname || "");
      setAddress(contact.address);
      setCreatedAt(contact.createdAt);
    }
    setLoading(false);
  }

  async function handleSave() {
    if (!address.trim()) {
      Alert.alert("Address is required");
      return;
    }
    setSaving(true);
    try {
      if (!contact) {
        throw new Error("Contact not found");
      }
      await updateContact({
        ...contact,
        id: id!,
        address: address.trim(),
        nickname: nickname.trim(),
        createdAt,
        updatedAt: Date.now(),
      });
      router.replace("/contacts");
    } catch (e) {
      Alert.alert("Failed to update contact");
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
        <Text style={{ color: theme.textSecondary }}>Loading...</Text>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <Text style={[styles.title, { color: theme.textPrimary }]}>Edit Contact</Text>
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
        <Text style={[styles.saveButtonText, { color: theme.primaryForeground }]}>{saving ? "Saving..." : "Save Changes"}</Text>
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
