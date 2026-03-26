import React, { useEffect, useState } from "react";
import { View, Text, FlatList, TouchableOpacity, StyleSheet, Alert } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { Contact } from "../types/contact";
import { getContacts, deleteContact } from "../services/contacts";
import { Link } from "expo-router";

export default function ContactsScreen() {
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
      <View style={styles.contactItem}>
        <View style={{ flex: 1 }}>
          <Text style={styles.nickname}>{item.nickname || "(No Nickname)"}</Text>
          <Text style={styles.address}>{item.address}</Text>
        </View>
        <Link href={{ pathname: "/payment-confirmation", params: { username: item.address } }} asChild>
          <TouchableOpacity style={styles.payButton}>
            <Text style={styles.payButtonText}>Pay</Text>
          </TouchableOpacity>
        </Link>
        <Link href={{ pathname: "/edit-contact", params: { id: item.id } }} asChild>
          <TouchableOpacity style={styles.editButton}>
            <Text style={styles.editButtonText}>Edit</Text>
          </TouchableOpacity>
        </Link>
        <TouchableOpacity style={styles.deleteButton} onPress={() => confirmDelete(item)}>
          <Text style={styles.deleteButtonText}>Delete</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <Text style={styles.title}>Contacts</Text>
      <Link href="/add-contact" asChild>
        <TouchableOpacity style={styles.addButton}>
          <Text style={styles.addButtonText}>Add Contact</Text>
        </TouchableOpacity>
      </Link>
      {loading ? (
        <Text>Loading...</Text>
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
  container: { flex: 1, backgroundColor: "#fff", padding: 16 },
  title: { fontSize: 28, fontWeight: "bold", marginBottom: 16, alignSelf: "center" },
  addButton: { backgroundColor: "#007AFF", padding: 12, borderRadius: 8, marginBottom: 16, alignSelf: "center" },
  addButtonText: { color: "#fff", fontWeight: "bold" },
  contactItem: { flexDirection: "row", alignItems: "center", padding: 12, borderBottomWidth: 1, borderColor: "#eee" },
  nickname: { fontSize: 18, fontWeight: "bold" },
  address: { fontSize: 14, color: "#666" },
  payButton: { marginLeft: 8, backgroundColor: "#4CD964", padding: 8, borderRadius: 6 },
  payButtonText: { color: "#fff", fontWeight: "bold" },
  editButton: { marginLeft: 8, backgroundColor: "#FFD700", padding: 8, borderRadius: 6 },
  editButtonText: { color: "#333" },
  deleteButton: { marginLeft: 8, backgroundColor: "#FF3B30", padding: 8, borderRadius: 6 },
  deleteButtonText: { color: "#fff" },
});
