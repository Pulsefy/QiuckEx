import React, { useEffect, useState } from "react";
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Alert, ScrollView } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { useLocalSearchParams, useRouter } from "expo-router";
import { getContacts, updateContact } from "../services/contacts";
import { Contact } from "../types/contact";
import { TagSelector, ContactTag } from "../components/TagSelector";
import { useTheme } from "../src/theme/ThemeContext";

export default function EditContactScreen() {
  const { theme } = useTheme();
  const { id } = useLocalSearchParams<{ id: string }>();
  const [nickname, setNickname] = useState("");
  const [address, setAddress] = useState("");
  const [selectedTags, setSelectedTags] = useState<ContactTag[]>([]);
  const [contact, setContact] = useState<Contact | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const router = useRouter();

  useEffect(() => {
    loadContact();
  }, [id]);

  async function loadContact() {
    setLoading(true);
    const contacts = await getContacts();
    const found = contacts.find((c) => c.id === id);
    if (found) {
      setContact(found);
      setNickname(found.nickname || "");
      setAddress(found.address);
      setSelectedTags((found.tags || []) as ContactTag[]);
    }
    setLoading(false);
  }

  function handleToggleTag(tag: ContactTag) {
    setSelectedTags(prev =>
      prev.includes(tag)
        ? prev.filter(t => t !== tag)
        : [...prev, tag]
    );
  }

  async function handleSave() {
    if (!address.trim()) {
      Alert.alert("Error", "Address is required");
      return;
    }
    
    if (!contact) {
      Alert.alert("Error", "Contact not found");
      return;
    }
    
    setSaving(true);
    try {
      await updateContact({
        ...contact,
        address: address.trim(),
        nickname: nickname.trim() || `Contact_${Date.now()}`,
        tags: selectedTags,
        updatedAt: Date.now(),
      });
      router.replace("/contacts");
    } catch (e) {
      Alert.alert("Error", "Failed to update contact");
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
        <Text style={{ color: theme.textSecondary, textAlign: "center", marginTop: 20 }}>
          Loading contact...
        </Text>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <ScrollView showsVerticalScrollIndicator={false}>
        <Text style={[styles.title, { color: theme.textPrimary }]}>Edit Contact</Text>
        
        <Text style={[styles.label, { color: theme.textSecondary }]}>Nickname (optional)</Text>
        <TextInput
          style={[styles.input, { borderColor: theme.inputBorder, backgroundColor: theme.inputBg, color: theme.inputText }]}
          placeholder="e.g., Alice Johnson"
          placeholderTextColor={theme.inputPlaceholder}
          value={nickname}
          onChangeText={setNickname}
        />
        
        <Text style={[styles.label, { color: theme.textSecondary }]}>Wallet Address *</Text>
        <TextInput
          style={[styles.input, { borderColor: theme.inputBorder, backgroundColor: theme.inputBg, color: theme.inputText }]}
          placeholder="0x..."
          placeholderTextColor={theme.inputPlaceholder}
          value={address}
          onChangeText={setAddress}
          autoCapitalize="none"
          autoCorrect={false}
        />
        
        <TagSelector selectedTags={selectedTags} onToggleTag={handleToggleTag} />
        
        <TouchableOpacity
          style={[styles.saveButton, { backgroundColor: theme.primary }, saving && { opacity: 0.6 }]}
          onPress={handleSave}
          disabled={saving}
        >
          <Text style={[styles.saveButtonText, { color: theme.primaryForeground }]}>
            {saving ? "Saving..." : "Save Changes"}
          </Text>
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16 },
  title: { fontSize: 28, fontWeight: "bold", marginBottom: 24, alignSelf: "center" },
  label: { fontSize: 14, fontWeight: "600", marginBottom: 6, marginTop: 8 },
  input: { borderWidth: 1, borderRadius: 8, padding: 12, marginBottom: 16, fontSize: 16 },
  saveButton: { padding: 14, borderRadius: 8, alignItems: "center", marginTop: 8, marginBottom: 32 },
  saveButtonText: { fontWeight: "bold", fontSize: 16 },
});
