import React, { useEffect, useState } from "react";
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Alert } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { useLocalSearchParams, useRouter } from "expo-router";
import { getContacts, saveContact, updateContact } from "../services/contacts";
import { Contact } from "../types/contact";

export default function EditContactScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const [nickname, setNickname] = useState("");
  const [address, setAddress] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const router = useRouter();

  useEffect(() => {
    loadContact();
  }, [id]);

  async function loadContact() {
    setLoading(true);
    const contacts = await getContacts();
    const contact = contacts.find((c) => c.id === id);
    if (contact) {
      setNickname(contact.nickname || "");
      setAddress(contact.address);
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
      await updateContact({
        id: id!,
        address: address.trim(),
        nickname: nickname.trim(),
        updatedAt: new Date().toISOString(),
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
      <SafeAreaView style={styles.container}>
        <Text>Loading...</Text>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <Text style={styles.title}>Edit Contact</Text>
      <TextInput
        style={styles.input}
        placeholder="Nickname (optional)"
        value={nickname}
        onChangeText={setNickname}
      />
      <TextInput
        style={styles.input}
        placeholder="Address (required)"
        value={address}
        onChangeText={setAddress}
        autoCapitalize="none"
        autoCorrect={false}
      />
      <TouchableOpacity
        style={[styles.saveButton, saving && { opacity: 0.6 }]}
        onPress={handleSave}
        disabled={saving}
      >
        <Text style={styles.saveButtonText}>{saving ? "Saving..." : "Save Changes"}</Text>
      </TouchableOpacity>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#fff", padding: 16 },
  title: { fontSize: 28, fontWeight: "bold", marginBottom: 16, alignSelf: "center" },
  input: { borderWidth: 1, borderColor: "#ccc", borderRadius: 8, padding: 12, marginBottom: 16, fontSize: 16 },
  saveButton: { backgroundColor: "#007AFF", padding: 14, borderRadius: 8, alignItems: "center" },
  saveButtonText: { color: "#fff", fontWeight: "bold", fontSize: 16 },
});
