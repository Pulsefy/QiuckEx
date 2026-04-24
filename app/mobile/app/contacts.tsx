import React, { useEffect, useState } from "react";
import { View, Text, FlatList, TouchableOpacity, StyleSheet, Alert } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { useRouter } from "expo-router";
import { Contact } from "../types/contact";
import { getContacts, deleteContact } from "../services/contacts";
import { TagFilter, ContactTag } from "../components/TagFilter";
import { SearchBar } from "../components/SearchBar";
import { useTheme } from "../src/theme/ThemeContext";

export default function ContactsScreen() {
  const { theme } = useTheme();
  const router = useRouter();
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [filteredContacts, setFilteredContacts] = useState<Contact[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedTags, setSelectedTags] = useState<ContactTag[]>([]);

  useEffect(() => {
    loadContacts();
  }, []);

  useEffect(() => {
    filterContacts();
  }, [searchQuery, selectedTags, contacts]);

  async function loadContacts() {
    setLoading(true);
    const data = await getContacts();
    setContacts(data);
    setLoading(false);
  }

  function filterContacts() {
    let filtered = [...contacts];
    
    // Apply search filter
    if (searchQuery) {
      filtered = filtered.filter(contact =>
        contact.nickname.toLowerCase().includes(searchQuery) ||
        contact.address.toLowerCase().includes(searchQuery)
      );
    }
    
    // Apply tag filter
    if (selectedTags.length > 0) {
      filtered = filtered.filter(contact =>
        contact.tags && contact.tags.some(tag => selectedTags.includes(tag as ContactTag))
      );
    }
    
    setFilteredContacts(filtered);
  }

  function handleTagPress(tag: ContactTag) {
    setSelectedTags(prev =>
      prev.includes(tag)
        ? prev.filter(t => t !== tag)
        : [...prev, tag]
    );
  }

  function handleQuickPay(contact: Contact) {
    router.push({
      pathname: "/payment-confirmation",
      params: { 
        username: contact.address,
        recipientName: contact.nickname,
        prefilled: "true"
      }
    });
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
      <View style={[styles.contactItem, { borderBottomColor: theme.borderLight }]}>
        <View style={styles.contactInfo}>
          <Text style={[styles.nickname, { color: theme.textPrimary }]}>
            {item.nickname || "(No Nickname)"}
          </Text>
          <Text style={[styles.address, { color: theme.textSecondary }]}>
            {item.address.slice(0, 20)}...
          </Text>
          {item.tags && item.tags.length > 0 && (
            <View style={styles.tagsContainer}>
              {item.tags.map((tag) => (
                <View key={tag} style={[styles.tag, { backgroundColor: theme.borderLight }]}>
                  <Text style={[styles.tagText, { color: theme.textSecondary }]}>{tag}</Text>
                </View>
              ))}
            </View>
          )}
        </View>
        
        <View style={styles.actionButtons}>
          <TouchableOpacity 
            style={[styles.quickPayButton, { backgroundColor: theme.status.success }]}
            onPress={() => handleQuickPay(item)}
          >
            <Text style={[styles.quickPayText, { color: theme.buttonPrimaryText }]}>Quick Pay</Text>
          </TouchableOpacity>
          
          <TouchableOpacity 
            style={[styles.editButton, { backgroundColor: theme.status.warning }]}
            onPress={() => router.push({ pathname: "/edit-contact", params: { id: item.id } })}
          >
            <Text style={[styles.editButtonText, { color: theme.textPrimary }]}>Edit</Text>
          </TouchableOpacity>
          
          <TouchableOpacity 
            style={[styles.deleteButton, { backgroundColor: theme.status.error }]}
            onPress={() => confirmDelete(item)}
          >
            <Text style={[styles.deleteButtonText, { color: theme.buttonDangerText }]}>Del</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  }

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <Text style={[styles.title, { color: theme.textPrimary }]}>Contacts</Text>
      
      <SearchBar onSearch={setSearchQuery} />
      <TagFilter selectedTags={selectedTags} onTagPress={handleTagPress} />
      
      <View style={styles.addButtonContainer}>
        <TouchableOpacity 
          style={[styles.addButton, { backgroundColor: theme.primary }]}
          onPress={() => router.push("/add-contact")}
        >
          <Text style={[styles.addButtonText, { color: theme.primaryForeground }]}>+ Add New Contact</Text>
        </TouchableOpacity>
      </View>
      
      {loading ? (
        <Text style={[styles.loadingText, { color: theme.textSecondary }]}>Loading contacts...</Text>
      ) : (
        <FlatList
          data={filteredContacts}
          keyExtractor={(item) => item.id}
          renderItem={renderItem}
          contentContainerStyle={styles.listContainer}
          ListEmptyComponent={
            <Text style={[styles.emptyText, { color: theme.textSecondary }]}>
              No contacts found matching your criteria
            </Text>
          }
        />
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16 },
  title: { fontSize: 28, fontWeight: "bold", marginBottom: 8, alignSelf: "center" },
  addButtonContainer: { alignItems: "center", marginVertical: 12 },
  addButton: { paddingHorizontal: 20, paddingVertical: 10, borderRadius: 8 },
  addButtonText: { fontWeight: "bold", fontSize: 16 },
  listContainer: { paddingBottom: 32 },
  contactItem: { 
    flexDirection: "row", 
    justifyContent: "space-between", 
    alignItems: "center", 
    padding: 12, 
    borderBottomWidth: 1 
  },
  contactInfo: { flex: 2 },
  nickname: { fontSize: 16, fontWeight: "bold" },
  address: { fontSize: 12, marginTop: 2 },
  tagsContainer: { flexDirection: "row", marginTop: 4, flexWrap: "wrap" },
  tag: { 
    paddingHorizontal: 8, 
    paddingVertical: 2, 
    borderRadius: 12, 
    marginRight: 4,
    marginBottom: 2
  },
  tagText: { fontSize: 10 },
  actionButtons: { flexDirection: "row", alignItems: "center", gap: 6 },
  quickPayButton: { paddingHorizontal: 10, paddingVertical: 6, borderRadius: 6 },
  quickPayText: { fontWeight: "bold", fontSize: 12 },
  editButton: { paddingHorizontal: 10, paddingVertical: 6, borderRadius: 6 },
  editButtonText: { fontWeight: "600", fontSize: 12 },
  deleteButton: { paddingHorizontal: 10, paddingVertical: 6, borderRadius: 6 },
  deleteButtonText: { fontWeight: "600", fontSize: 12 },
  loadingText: { textAlign: "center", marginTop: 20 },
  emptyText: { textAlign: "center", marginTop: 20, fontSize: 14 },
});
