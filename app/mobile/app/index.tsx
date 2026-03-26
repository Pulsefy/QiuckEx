import { Link } from "expo-router";
import React from "react";
import { StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import NotificationCenter from "../components/notifications/NotificationCenter";

export default function HomeScreen() {
  // Pay Again shortcut logic
  const [recentContacts, setRecentContacts] = React.useState([]);
  React.useEffect(() => {
    async function loadContacts() {
      try {
        const { getContacts } = require("../services/contacts");
        const contacts = await getContacts();
        setRecentContacts(contacts.slice(0, 3));
      } catch {}
    }
    loadContacts();
  }, []);

  return (
    <SafeAreaView style={styles.container}>
      <View style={{ position: "absolute", top: 12, right: 16, zIndex: 100 }}>
        {/* Bell */}
        <NotificationCenter />
      </View>
      <View style={styles.content}>
        <Text style={styles.title}>QuickEx</Text>

        <Text style={styles.subtitle}>
          Fast, privacy-focused payment link platform built on Stellar.
        </Text>

        {/* Pay Again Shortcut */}
        {recentContacts.length > 0 && (
          <View style={{ width: "100%", marginBottom: 20 }}>
            <Text style={{ fontWeight: "bold", fontSize: 18, marginBottom: 8 }}>Pay Again</Text>
            {recentContacts.map((contact) => (
              <Link
                key={contact.id}
                href={{ pathname: "/payment-confirmation", params: { username: contact.address } }}
                asChild
              >
                <TouchableOpacity style={{ backgroundColor: "#F5F5F5", padding: 12, borderRadius: 8, marginBottom: 8 }}>
                  <Text style={{ fontWeight: "bold", fontSize: 16 }}>{contact.nickname || contact.address}</Text>
                  <Text style={{ color: "#888" }}>{contact.address}</Text>
                </TouchableOpacity>
              </Link>
            ))}
          </View>
        )}

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Instant Payments</Text>
          <Text style={styles.cardText}>
            Receive USDC, XLM, or any Stellar asset directly to your
            self-custody wallet.
          </Text>
        </View>

        <Link href="/scan-to-pay" asChild>
          <TouchableOpacity style={styles.primaryButton}>
            <Text style={styles.primaryButtonText}>Scan to Pay</Text>
          </TouchableOpacity>
        </Link>

        <Link href="/wallet-connect" asChild>
          <TouchableOpacity style={styles.primaryButton}>
            <Text style={styles.primaryButtonText}>Connect Wallet</Text>
          </TouchableOpacity>
        </Link>

        <Link href="/contacts" asChild>
          <TouchableOpacity style={styles.primaryButton}>
            <Text style={styles.primaryButtonText}>Contacts</Text>
          </TouchableOpacity>
        </Link>

        <Link href="/security" asChild>
          <TouchableOpacity style={styles.secondaryButton}>
            <Text style={styles.secondaryButtonText}>Security Settings</Text>
          </TouchableOpacity>
        </Link>

        {/* Quick Receive */}
        <Link href="/quick-receive" asChild>
          <TouchableOpacity style={styles.quickReceiveButton}>
            <Text style={styles.quickReceiveButtonText}>Quick Receive</Text>
          </TouchableOpacity>
        </Link>

        {/* Transaction History */}
        <Link href="/transactions" asChild>
          <TouchableOpacity style={styles.secondaryButton}>
            <Text style={styles.secondaryButtonText}>Transaction History</Text>
          </TouchableOpacity>
        </Link>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#ffffff",
  },
  content: {
    flex: 1,
    padding: 24,
    justifyContent: "center",
    alignItems: "center",
  },
  title: {
    fontSize: 42,
    fontWeight: "bold",
    color: "#000",
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 18,
    color: "#666",
    textAlign: "center",
    marginBottom: 40,
  },
  card: {
    width: "100%",
    padding: 20,
    borderRadius: 12,
    backgroundColor: "#f5f5f5",
    marginBottom: 30,
  },
  cardTitle: {
    fontSize: 20,
    fontWeight: "600",
    color: "#333",
    marginBottom: 8,
  },
  cardText: {
    fontSize: 16,
    color: "#555",
    lineHeight: 22,
  },

  /* Primary Button */
  primaryButton: {
    backgroundColor: "#000",
    paddingVertical: 16,
    paddingHorizontal: 32,
    borderRadius: 8,
    width: "100%",
    alignItems: "center",
    marginBottom: 12,
  },
  primaryButtonText: {
    color: "#fff",
    fontSize: 18,
    fontWeight: "bold",
  },
  /* Quick Receive Button */
  quickReceiveButton: {
    backgroundColor: "#10B981",
    paddingVertical: 16,
    paddingHorizontal: 32,
    borderRadius: 8,
    width: "100%",
    alignItems: "center",
    marginBottom: 12,
  },
  quickReceiveButtonText: {
    color: "#fff",
    fontSize: 18,
    fontWeight: "600",
  },

  /* Secondary Button */
  secondaryButton: {
    paddingVertical: 16,
    paddingHorizontal: 32,
    borderRadius: 8,
    width: "100%",
    alignItems: "center",
    borderWidth: 1,
    borderColor: "#000",
  },
  secondaryButtonText: {
    color: "#000",
    fontSize: 18,
    fontWeight: "600",
  },
});
