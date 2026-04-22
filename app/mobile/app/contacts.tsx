import React, { useEffect, useState } from "react";
import { View, Text, FlatList, TouchableOpacity, StyleSheet, Alert } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { Contact } from "../types/contact";
import { getContacts, deleteContact } from "../services/contacts";
import { Link } from "expo-router";
import { useTheme } from "../src/theme/ThemeContext";

export default function ContactsScreen() {
  const { theme } = useTheme();
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadContacts();
  }, []);

  async function loadContacts() {
    setLoading(true);
    const data = await getContacts();
    setContacts(data);
    setLoading(false);
  }

  function confirmDelete(contact: Contact) {
    Alert.alert(
      "Delete Contact",
      `Are you sure you want to delete ${contact.nickname || contact.address}?`,
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Delete",
          style: "destructive",
          onPress: async () => {
            await deleteContact(contact.id);
            loadContacts();
          },
        },
      ]
    );
  }

  function renderItem({ item }: { item: Contact }) {
    return (
      <View style={[styles.contactItem, { borderColor: theme.borderLight }]}>
        <View style={{ flex: 1 }}>
          <Text style={[styles.nickname, { color: theme.textPrimary }]}>{item.nickname || "(No Nickname)"}</Text>
          <Text style={[styles.address, { color: theme.textSecondary }]}>{item.address}</Text>
        </View>
        <Link href={{ pathname: "/payment-confirmation", params: { username: item.address } }} asChild>
          <TouchableOpacity style={[styles.payButton, { backgroundColor: theme.status.success }]}>
            <Text style={[styles.payButtonText, { color: theme.buttonPrimaryText }]}>Pay</Text>
          </TouchableOpacity>
        </Link>
        <Link href={{ pathname: "/edit-contact", params: { id: item.id } }} asChild>
          <TouchableOpacity style={[styles.editButton, { backgroundColor: theme.status.warning }]}>
            <Text style={[styles.editButtonText, { color: theme.textPrimary }]}>Edit</Text>
          </TouchableOpacity>
        </Link>
        <TouchableOpacity style={[styles.deleteButton, { backgroundColor: theme.status.error }]} onPress={() => confirmDelete(item)}>
          <Text style={[styles.deleteButtonText, { color: theme.buttonDangerText }]}>Delete</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <Text style={[styles.title, { color: theme.textPrimary }]}>Contacts</Text>
      <Link href="/add-contact" asChild>
        <TouchableOpacity style={[styles.addButton, { backgroundColor: theme.primary }]}>
          <Text style={[styles.addButtonText, { color: theme.primaryForeground }]}>Add Contact</Text>
        </TouchableOpacity>
      </Link>
      {loading ? (
        <Text style={{ color: theme.textSecondary }}>Loading...</Text>
      ) : (
        <FlatList
          data={contacts}
          keyExtractor={(item) => item.id}
          renderItem={renderItem}
          contentContainerStyle={{ paddingBottom: 32 }}
        />
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16 },
  title: { fontSize: 28, fontWeight: "bold", marginBottom: 16, alignSelf: "center" },
  addButton: { padding: 12, borderRadius: 8, marginBottom: 16, alignSelf: "center" },
  addButtonText: { fontWeight: "bold" },
  contactItem: { flexDirection: "row", alignItems: "center", padding: 12, borderBottomWidth: 1 },
  nickname: { fontSize: 18, fontWeight: "bold" },
  address: { fontSize: 14 },
  payButton: { marginLeft: 8, padding: 8, borderRadius: 6 },
  payButtonText: { fontWeight: "bold" },
  editButton: { marginLeft: 8, padding: 8, borderRadius: 6 },
  editButtonText: { fontWeight: "600" },
  deleteButton: { marginLeft: 8, padding: 8, borderRadius: 6 },
  deleteButtonText: { fontWeight: "600" },
});
