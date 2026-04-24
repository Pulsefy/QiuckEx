import React, { useState } from "react";
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Alert, ScrollView } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { useRouter } from "expo-router";
import { saveContact } from "../services/contacts";
import { TagSelector, ContactTag } from "../components/TagSelector";
import { useTheme } from "../src/theme/ThemeContext";

export default function AddContactScreen() {
  const { theme } = useTheme();
  const [nickname, setNickname] = useState("");
  const [address, setAddress] = useState("");
  const [selectedTags, setSelectedTags] = useState<ContactTag[]>([]);
  const [saving, setSaving] = useState(false);
  const router = useRouter();

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
    
    if (!address.startsWith("0x") && address.length !== 42) {
      Alert.alert("Error", "Please enter a valid wallet address");
      return;
    }
    
    setSaving(true);
    try {
      await saveContact({
        address: address.trim(),
        nickname: nickname.trim() || `Contact_${Date.now()}`,
        tags: selectedTags,
      } as any);
      router.replace("/contacts");
    } catch (e) {
      Alert.alert("Error", "Failed to save contact");
    } finally {
      setSaving(false);
    }
  }

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <ScrollView showsVerticalScrollIndicator={false}>
        <Text style={[styles.title, { color: theme.textPrimary }]}>Add Contact</Text>
        
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
            {saving ? "Saving..." : "Save Contact"}
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
