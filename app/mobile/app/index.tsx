import { Link, useRouter } from "expo-router";
import React, { useEffect } from "react";
import { StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import NotificationCenter from "../components/notifications/NotificationCenter";
import { useOnboarding } from "../hooks/useOnboarding";
import { useTheme } from "../src/theme/ThemeContext";

export default function HomeScreen() {
  const router = useRouter();
  const { theme } = useTheme();
  const { hasCompletedOnboarding, isLoading } = useOnboarding();
  // Pay Again shortcut logic
  const [recentContacts, setRecentContacts] = React.useState<any[]>([]);
  
  // Redirect to onboarding if not completed
  useEffect(() => {
    if (!isLoading && !hasCompletedOnboarding) {
      router.replace('/onboarding');
    }
  }, [isLoading, hasCompletedOnboarding, router]);

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

  if (isLoading || !hasCompletedOnboarding) {
    return null; // Show loading while checking onboarding status
  }

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <View style={{ position: "absolute", top: 12, right: 16, zIndex: 100 }}>
        {/* Bell */}
        <NotificationCenter />
      </View>
      <View style={styles.content}>
        <Text style={[styles.title, { color: theme.textPrimary }]}>QuickEx</Text>

        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
          Fast, privacy-focused payment link platform built on Stellar.
        </Text>

        {/* Pay Again Shortcut */}
        {recentContacts.length > 0 && (
          <View style={{ width: "100%", marginBottom: 20 }}>
            <Text style={{ fontWeight: "bold", fontSize: 18, marginBottom: 8, color: theme.textPrimary }}>Pay Again</Text>
            {recentContacts.map((contact) => (
              <Link
                key={contact.id}
                href={{ pathname: "/payment-confirmation", params: { username: contact.address } }}
                asChild
              >
                <TouchableOpacity style={{ backgroundColor: theme.surface, padding: 12, borderRadius: 8, marginBottom: 8 }}>
                  <Text style={{ fontWeight: "bold", fontSize: 16, color: theme.textPrimary }}>{contact.nickname || contact.address}</Text>
                  <Text style={{ color: theme.textSecondary }}>{contact.address}</Text>
                </TouchableOpacity>
              </Link>
            ))}
          </View>
        )}

        <View style={[styles.card, { backgroundColor: theme.surface }]}>
          <Text style={[styles.cardTitle, { color: theme.textPrimary }]}>Instant Payments</Text>
          <Text style={[styles.cardText, { color: theme.textSecondary }]}>
            Receive USDC, XLM, or any Stellar asset directly to your
            self-custody wallet.
          </Text>
        </View>

        <Link href="/scan-to-pay" asChild>
          <TouchableOpacity style={[styles.primaryButton, { backgroundColor: theme.buttonPrimaryBg }]}>
            <Text style={[styles.primaryButtonText, { color: theme.buttonPrimaryText }]}>Scan to Pay</Text>
          </TouchableOpacity>
        </Link>

        <Link href="/wallet-connect" asChild>
          <TouchableOpacity style={[styles.primaryButton, { backgroundColor: theme.buttonPrimaryBg }]}>
            <Text style={[styles.primaryButtonText, { color: theme.buttonPrimaryText }]}>Connect Wallet</Text>
          </TouchableOpacity>
        </Link>

        <Link href="/contacts" asChild>
          <TouchableOpacity style={[styles.primaryButton, { backgroundColor: theme.buttonPrimaryBg }]}>
            <Text style={[styles.primaryButtonText, { color: theme.buttonPrimaryText }]}>Contacts</Text>
          </TouchableOpacity>
        </Link>

        <Link href="/security" asChild>
          <TouchableOpacity style={[styles.secondaryButton, { borderColor: theme.buttonSecondaryBorder }]}>
            <Text style={[styles.secondaryButtonText, { color: theme.buttonSecondaryText }]}>Security Settings</Text>
          </TouchableOpacity>
        </Link>

        {/* Quick Receive */}
        <Link href="/quick-receive" asChild>
          <TouchableOpacity style={[styles.quickReceiveButton, { backgroundColor: theme.status.success }]}>
            <Text style={[styles.quickReceiveButtonText, { color: theme.buttonPrimaryText }]}>Quick Receive</Text>
          </TouchableOpacity>
        </Link>

        {/* Link Generator */}
        <Link href="/link-generator" asChild>
          <TouchableOpacity style={[styles.linkGenButton, { backgroundColor: theme.status.info }]}>
            <Text style={[styles.linkGenButtonText, { color: theme.buttonPrimaryText }]}>Generate Link</Text>
          </TouchableOpacity>
        </Link>

        {/* Transaction History */}
        <Link href="/transactions" asChild>
          <TouchableOpacity style={[styles.secondaryButton, { borderColor: theme.buttonSecondaryBorder }]}>
            <Text style={[styles.secondaryButtonText, { color: theme.buttonSecondaryText }]}>Transaction History</Text>
          </TouchableOpacity>
        </Link>

        {/* Settings */}
        <Link href="/settings" asChild>
          <TouchableOpacity style={[styles.secondaryButton, { borderColor: theme.buttonSecondaryBorder, marginTop: 12 }]}>
            <Text style={[styles.secondaryButtonText, { color: theme.buttonSecondaryText }]}>⚙️ Settings</Text>
          </TouchableOpacity>
        </Link>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
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
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 18,
    textAlign: "center",
    marginBottom: 40,
  },
  card: {
    width: "100%",
    padding: 20,
    borderRadius: 12,
    marginBottom: 30,
  },
  cardTitle: {
    fontSize: 20,
    fontWeight: "600",
    marginBottom: 8,
  },
  cardText: {
    fontSize: 16,
    lineHeight: 22,
  },

  /* Primary Button */
  primaryButton: {
    paddingVertical: 16,
    paddingHorizontal: 32,
    borderRadius: 8,
    width: "100%",
    alignItems: "center",
    marginBottom: 12,
  },
  primaryButtonText: {
    fontSize: 18,
    fontWeight: "bold",
  },
  /* Quick Receive Button */
  quickReceiveButton: {
    paddingVertical: 16,
    paddingHorizontal: 32,
    borderRadius: 8,
    width: "100%",
    alignItems: "center",
    marginBottom: 12,
  },
  quickReceiveButtonText: {
    fontSize: 18,
    fontWeight: "600",
  },

  /* Link Generator Button */
  linkGenButton: {
    paddingVertical: 16,
    paddingHorizontal: 32,
    borderRadius: 8,
    width: "100%",
    alignItems: "center",
    marginBottom: 12,
  },
  linkGenButtonText: {
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
  },
  secondaryButtonText: {
    fontSize: 18,
    fontWeight: "600",
  },
});
