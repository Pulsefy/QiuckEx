import { Link } from "expo-router";
import React, { useEffect, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View, Alert } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { Ionicons } from "@expo/vector-icons";

import { useSecurity } from "@/hooks/use-security";
import {
  getWalletSession,
  isSessionRestorable,
} from "@/services/wallet-session";
import { getSessionExpiryExplanation } from "@/services/security";
import { useTheme } from "../src/theme/ThemeContext";
import { CrashReportingService } from "@/services/CrashReportingService";

interface SecurityCheckItem {
  id: string;
  title: string;
  description: string;
  status: "pass" | "warning" | "error";
  actionText?: string;
  actionLink?: string;
}

interface ActiveSession {
  id: string;
  device: string;
  location: string;
  lastActive: string;
  isCurrent: boolean;
}

interface LoginHistory {
  id: string;
  timestamp: string;
  device: string;
  location: string;
  status: 'success' | 'failed';
}

type TabType = 'overview' | 'sessions' | 'history' | 'setup' | 'tips';

const SECURITY_TIPS = [
  {
    title: 'Use a Strong PIN',
    description: 'Your PIN should be unique and difficult to guess. Avoid birthdays or sequential numbers.',
    icon: 'key',
  },
  {
    title: 'Enable Biometrics',
    description: 'Use fingerprint or face recognition for faster and more secure app access.',
    icon: 'finger-print',
  },
  {
    title: 'Review Active Sessions',
    description: 'Regularly check and revoke access from devices you no longer use.',
    icon: 'shield-checkmark',
  },
  {
    title: 'Monitor Login History',
    description: 'Keep an eye on your login activity to detect unauthorized access.',
    icon: 'time',
  },
  {
    title: 'Never Share Your PIN',
    description: 'QuickEx support will never ask for your PIN. Keep it private at all times.',
    icon: 'warning',
  },
  {
    title: 'Update Regularly',
    description: 'Keep the QuickEx app updated to get the latest security patches.',
    icon: 'refresh',
  },
];

const MOCK_SESSIONS: ActiveSession[] = [
  {
    id: 'session-1',
    device: 'iPhone 15 Pro',
    location: 'Lagos, Nigeria',
    lastActive: '2 minutes ago',
    isCurrent: true,
  },
  {
    id: 'session-2',
    device: 'MacBook Pro',
    location: 'Lagos, Nigeria',
    lastActive: '2 hours ago',
    isCurrent: false,
  },
  {
    id: 'session-3',
    device: 'iPad Air',
    location: 'Abuja, Nigeria',
    lastActive: '1 day ago',
    isCurrent: false,
  },
];

const MOCK_LOGIN_HISTORY: LoginHistory[] = [
  {
    id: 'login-1',
    timestamp: new Date(Date.now() - 2 * 60000).toISOString(),
    device: 'iPhone 15 Pro',
    location: 'Lagos, Nigeria',
    status: 'success',
  },
  {
    id: 'login-2',
    timestamp: new Date(Date.now() - 2 * 3600000).toISOString(),
    device: 'MacBook Pro',
    location: 'Lagos, Nigeria',
    status: 'success',
  },
  {
    id: 'login-3',
    timestamp: new Date(Date.now() - 24 * 3600000).toISOString(),
    device: 'iPad Air',
    location: 'Abuja, Nigeria',
    status: 'success',
  },
  {
    id: 'login-4',
    timestamp: new Date(Date.now() - 48 * 3600000).toISOString(),
    device: 'Unknown Device',
    location: 'Port Harcourt, Nigeria',
    status: 'failed',
  },
];

export default function SecurityCenterScreen() {
  const { theme } = useTheme();
  const { isBiometricAvailable, hasPinConfigured, settings, setBiometricLockEnabled } = useSecurity();
  const [securityItems, setSecurityItems] = useState<SecurityCheckItem[]>([]);
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [sessions, setSessions] = useState<ActiveSession[]>(MOCK_SESSIONS);

      const items: SecurityCheckItem[] = [];

      if (isBiometricAvailable) {
        if (settings.biometricLockEnabled) {
          items.push({
            id: "biometrics",
            title: "Biometric Lock Enabled",
            description: "Your device biometrics are protecting sensitive actions.",
            status: "pass",
          });
        } else {
          items.push({
            id: "biometrics",
            title: "Enable Biometric Lock",
            description: "Add an extra layer of security with biometric authentication.",
            status: "warning",
            actionText: "Enable",
            actionLink: "/security",
          });
        }
      } else {
        items.push({
          id: "biometrics",
          title: "Biometrics Unavailable",
          description: "Biometric hardware is not available on this device.",
          status: "warning",
        });
      }

      if (hasPinConfigured) {
        items.push({
          id: "pin",
          title: "Fallback PIN Configured",
          description: "You have a secure PIN as a backup authentication method.",
          status: "pass",
        });
      } else {
        items.push({
          id: "pin",
          title: "Set Fallback PIN",
          description: "Configure a PIN for when biometrics fail or are unavailable.",
          status: "error",
          actionText: "Set PIN",
          actionLink: "/security",
        });
      }

      const session = await getWalletSession();
      setWalletSession(session);
      setSessionExplanation(await getSessionExpiryExplanation());
      if (session) {
        const isRestorable = isSessionRestorable(session);
        if (isRestorable) {
          items.push({
            id: "session",
            title: "Active Wallet Session",
            description: "Your wallet session is active and secure.",
            status: "pass",
          });
        } else {
          items.push({
            id: "session",
            title: "Session Expired",
            description: "Your wallet session has expired. Reconnect your wallet.",
            status: "warning",
            actionText: "Reconnect",
            actionLink: "/",
          });
        }
      } else {
        items.push({
          id: "session",
          title: "No Wallet Connected",
          description: "Connect a wallet to start using the app securely.",
          status: "warning",
          actionText: "Connect Wallet",
          actionLink: "/",
        });
      }

      setSecurityItems(items);
      setLoading(false);
      setRefreshing(false);
  }, [isBiometricAvailable, hasPinConfigured, settings]);

  const handleRevokeSession = (sessionId: string) => {
    Alert.alert(
      'Revoke Session',
      'Are you sure you want to sign out from this device?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Revoke',
          style: 'destructive',
          onPress: () => {
            CrashReportingService.recordUserAction('Session revoked', { sessionId });
            setSessions(sessions.filter(s => s.id !== sessionId));
            Alert.alert('Session Revoked', 'You have been signed out from this device.');
          },
        },
      ],
    );
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "pass":
        return "#10B981";
      case "warning":
        return "#F59E0B";
      case "error":
        return "#EF4444";
      default:
        return theme.textSecondary;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "pass":
        return "✓";
      case "warning":
        return "⚠";
      case "error":
        return "!";
      default:
        return "";
    }
  };

  const overallScore = securityItems.filter(
    (item) => item.status === "pass",
  ).length;
  const totalItems = securityItems.length;
  const securityLevel =
    overallScore === totalItems
      ? "Strong"
      : overallScore >= totalItems / 2
        ? "Moderate"
        : "Needs Attention";

  const renderOverviewTab = () => (
    <>
      <View
        style={[
          styles.scoreCard,
          { backgroundColor: theme.surface, borderColor: theme.border },
        ]}
      >
        <Text style={[styles.scoreLabel, { color: theme.textSecondary }]}>
          Security Level
        </Text>
        <Text
          style={[
            styles.scoreValue,
            {
              color:
                securityLevel === "Strong"
                  ? "#10B981"
                  : securityLevel === "Moderate"
                    ? "#F59E0B"
                    : "#EF4444",
            },
          ]}
        >
          {securityLevel}
        </Text>
        <Text style={[styles.scoreDetail, { color: theme.textSecondary }]}>
          {overallScore} of {totalItems} checks passed
        </Text>
      </View>

      <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
        Security Checklist
      </Text>

      {securityItems.map((item) => (
        <View
          key={item.id}
          style={[
            styles.checkItem,
            {
              backgroundColor: theme.surface,
              borderColor: theme.border,
              borderLeftColor: getStatusColor(item.status),
            },
          ]}
        >
          <View style={styles.checkHeader}>
            <View
              style={[
                styles.statusIcon,
                { backgroundColor: getStatusColor(item.status) },
              ]}
            >
              <Text style={styles.statusIconText}>
                {getStatusIcon(item.status)}
              </Text>
            </View>
            <View style={styles.checkContent}>
              <Text style={[styles.checkTitle, { color: theme.textPrimary }]}>
                {item.title}
              </Text>
              <Text
                style={[
                  styles.checkDescription,
                  { color: theme.textSecondary },
                ]}
              >
                {item.description}
              </Text>
            </View>
          </View>
          {item.actionText && item.actionLink && (
            <Link href={item.actionLink} asChild>
              <Pressable
                style={[
                  styles.actionButton,
                  { backgroundColor: theme.buttonPrimaryBg },
                ]}
              >
                <Text
                  style={[
                    styles.actionButtonText,
                    { color: theme.buttonPrimaryText },
                  ]}
                >
                  {item.actionText}
                </Text>
              </Pressable>
            </Link>
          )}
        </View>
      ))}
    </>
  );

  const renderSessionsTab = () => (
    <>
      <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
        Active Sessions ({sessions.length})
      </Text>

      {sessions.map((session) => (
        <View
          key={session.id}
          style={[
            styles.sessionCard,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <View style={styles.sessionHeader}>
            <View style={styles.sessionIconContainer}>
              <Ionicons name="phone-portrait" size={24} color={theme.buttonPrimaryBg} />
            </View>
            <View style={{ flex: 1 }}>
              <Text style={[styles.sessionDevice, { color: theme.textPrimary }]}>
                {session.device}
                {session.isCurrent && (
                  <Text style={[styles.currentBadge, { color: theme.buttonPrimaryBg }]}>
                    {' '}(Current)
                  </Text>
                )}
              </Text>
              <Text style={[styles.sessionInfo, { color: theme.textSecondary }]}>
                {session.location}
              </Text>
              <Text style={[styles.sessionTime, { color: theme.textTertiary }]}>
                Last active: {session.lastActive}
              </Text>
            </View>
          </View>

          {!session.isCurrent && (
            <Pressable
              style={[styles.revokeButton, { borderColor: '#EF4444' }]}
              onPress={() => handleRevokeSession(session.id)}
            >
              <Ionicons name="close-circle" size={16} color="#EF4444" />
              <Text style={[styles.revokeButtonText, { color: '#EF4444' }]}>
                Revoke
              </Text>
            </Pressable>
          )}
        </View>
      ))}
    </>
  );

  const renderHistoryTab = () => (
    <>
      <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
        Login History
      </Text>

      {MOCK_LOGIN_HISTORY.map((login) => (
        <View
          key={login.id}
          style={[
            styles.historyItem,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <View style={styles.historyItemContent}>
            <View style={styles.historyIconContainer}>
              <Ionicons
                name={login.status === 'success' ? 'checkmark-circle' : 'close-circle'}
                size={20}
                color={login.status === 'success' ? '#10B981' : '#EF4444'}
              />
            </View>
            <View style={{ flex: 1 }}>
              <Text style={[styles.historyTime, { color: theme.textPrimary }]}>
                {new Date(login.timestamp).toLocaleString()}
              </Text>
              <Text style={[styles.historyDetails, { color: theme.textSecondary }]}>
                {login.device} • {login.location}
              </Text>
            </View>
            <Text
              style={[
                styles.historyStatus,
                {
                  color: login.status === 'success' ? '#10B981' : '#EF4444',
                  fontWeight: '600',
                },
              ]}
            >
              {login.status === 'success' ? 'Success' : 'Failed'}
            </Text>
          </View>
        </View>
      ))}
    </>
  );

  const renderSetupTab = () => (
    <>
      <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
        Two-Factor Authentication
      </Text>

      <View
        style={[
          styles.setupCard,
          { backgroundColor: theme.surface, borderColor: theme.border },
        ]}
      >
        <View style={styles.setupHeader}>
          <Ionicons name="shield-checkmark" size={28} color={theme.buttonPrimaryBg} />
          <View style={{ flex: 1 }}>
            <Text style={[styles.setupTitle, { color: theme.textPrimary }]}>
              Two-Factor Authentication
            </Text>
            <Text style={[styles.setupDescription, { color: theme.textSecondary }]}>
              Add an extra layer of security to your account
            </Text>
          </View>
        </View>

        <Text style={[styles.setupSteps, { color: theme.textPrimary }]}>
          Setup Steps:
        </Text>

        <View style={styles.stepsList}>
          {[
            'Download an authenticator app (Google Authenticator, Authy)',
            'Open Settings → Security → 2FA Setup',
            'Scan the QR code with your authenticator app',
            'Enter the 6-digit code to verify',
            'Save backup codes in a secure location',
          ].map((step, index) => (
            <View key={index} style={styles.step}>
              <Text style={[styles.stepNumber, { color: theme.buttonPrimaryBg }]}>
                {index + 1}
              </Text>
              <Text style={[styles.stepText, { color: theme.textSecondary }]}>
                {step}
              </Text>
            </View>
          ))}
        </View>

        <Link href="/settings" asChild>
          <Pressable
            style={[styles.setupButton, { backgroundColor: theme.buttonPrimaryBg }]}
          >
            <Text style={[styles.setupButtonText, { color: theme.buttonPrimaryText }]}>
              Go to Security Settings
            </Text>
          </Pressable>
        </Link>
      </View>
    </>
  );

  const renderTipsTab = () => (
    <>
      <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>
        Security Tips
      </Text>

      {SECURITY_TIPS.map((tip, index) => (
        <View
          key={index}
          style={[
            styles.tipCard,
            { backgroundColor: theme.surface, borderColor: theme.border },
          ]}
        >
          <View style={styles.tipIconContainer}>
            <Ionicons name={tip.icon as any} size={24} color={theme.buttonPrimaryBg} />
          </View>
          <View style={{ flex: 1 }}>
            <Text style={[styles.tipTitle, { color: theme.textPrimary }]}>
              {tip.title}
            </Text>
            <Text style={[styles.tipDescription, { color: theme.textSecondary }]}>
              {tip.description}
            </Text>
          </View>
        </View>
      ))}
    </>
  );

  return (
    <SafeAreaView
      style={[styles.container, { backgroundColor: theme.background }]}
    >
      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.content}
        showsVerticalScrollIndicator={false}
      >
        <Text style={[styles.title, { color: theme.textPrimary }]}>
          Security Center
        </Text>
        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
          Manage your account security and devices
        </Text>

        {/* Tab Navigation */}
        <ScrollView
          horizontal
          showsHorizontalScrollIndicator={false}
          style={styles.tabBar}
          contentContainerStyle={styles.tabBarContent}
        >
          {(['overview', 'sessions', 'history', 'setup', 'tips'] as TabType[]).map(
            (tab) => (
              <Pressable
                key={tab}
                style={[
                  styles.tab,
                  activeTab === tab && [
                    styles.tabActive,
                    { borderBottomColor: theme.buttonPrimaryBg },
                  ],
                ]}
                onPress={() => setActiveTab(tab)}
              >
                <Text
                  style={[
                    styles.tabText,
                    {
                      color:
                        activeTab === tab ? theme.buttonPrimaryBg : theme.textSecondary,
                    },
                  ]}
                >
                  {tab.charAt(0).toUpperCase() + tab.slice(1)}
                </Text>
              </Pressable>
            ),
          )}
        </ScrollView>

        {/* Tab Content */}
        {activeTab === 'overview' && renderOverviewTab()}
        {activeTab === 'sessions' && renderSessionsTab()}
        {activeTab === 'history' && renderHistoryTab()}
        {activeTab === 'setup' && renderSetupTab()}
        {activeTab === 'tips' && renderTipsTab()}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  scrollView: {
    flex: 1,
  },
  content: {
    padding: 24,
    gap: 16,
    paddingBottom: 40,
  },
  title: {
    fontSize: 34,
    fontWeight: "800",
    marginBottom: 4,
  },
  subtitle: {
    fontSize: 16,
    lineHeight: 22,
    marginBottom: 8,
  },
  // Tab Navigation
  tabBar: {
    marginHorizontal: -24,
    marginBottom: 12,
  },
  tabBarContent: {
    paddingHorizontal: 24,
    gap: 8,
  },
  tab: {
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderBottomWidth: 2,
    borderBottomColor: "transparent",
  },
  tabActive: {
    borderBottomWidth: 2,
  },
  tabText: {
    fontSize: 14,
    fontWeight: "600",
  },
  toolbar: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 12,
  },
  updatedText: {
    flex: 1,
    fontSize: 12,
  },
  refreshButton: {
    borderWidth: 1,
    borderRadius: 10,
    paddingHorizontal: 14,
    paddingVertical: 9,
  },
  refreshButtonText: {
    fontSize: 13,
    fontWeight: "700",
  },
  scoreCard: {
    borderRadius: 16,
    padding: 20,
    borderWidth: 1,
    alignItems: "center",
  },
  scoreLabel: {
    fontSize: 14,
    fontWeight: "600",
    textTransform: "uppercase",
  },
  scoreValue: {
    fontSize: 32,
    fontWeight: "800",
    marginTop: 8,
  },
  scoreDetail: {
    fontSize: 14,
    marginTop: 4,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: "700",
    marginTop: 8,
  },
  checkItem: {
    borderRadius: 12,
    padding: 16,
    borderWidth: 1,
    borderLeftWidth: 4,
    gap: 12,
  },
  checkHeader: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 12,
  },
  statusIcon: {
    width: 28,
    height: 28,
    borderRadius: 14,
    alignItems: "center",
    justifyContent: "center",
  },
  statusIconText: {
    color: "white",
    fontSize: 16,
    fontWeight: "700",
  },
  checkContent: {
    flex: 1,
  },
  checkTitle: {
    fontSize: 16,
    fontWeight: "700",
    marginBottom: 4,
  },
  checkDescription: {
    fontSize: 14,
    lineHeight: 20,
  },
  actionButton: {
    borderRadius: 8,
    paddingVertical: 10,
    paddingHorizontal: 16,
    alignSelf: "flex-start",
  },
  actionButtonText: {
    fontSize: 14,
    fontWeight: "700",
  },
  // Sessions Tab
  sessionCard: {
    borderRadius: 12,
    padding: 16,
    borderWidth: 1,
    marginBottom: 12,
    gap: 12,
  },
  sessionHeader: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
  },
  sessionIconContainer: {
    width: 48,
    height: 48,
    borderRadius: 24,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(59, 130, 246, 0.1)",
  },
  sessionDevice: {
    fontSize: 15,
    fontWeight: "700",
    marginBottom: 2,
  },
  currentBadge: {
    fontSize: 12,
    fontWeight: "600",
  },
  sessionInfo: {
    fontSize: 13,
    marginBottom: 2,
  },
  sessionTime: {
    fontSize: 12,
  },
  revokeButton: {
    flexDirection: "row",
    paddingVertical: 8,
    paddingHorizontal: 12,
    borderRadius: 8,
    borderWidth: 1.5,
    alignItems: "center",
    justifyContent: "center",
    gap: 6,
    alignSelf: "flex-start",
  },
  revokeButtonText: {
    fontSize: 13,
    fontWeight: "600",
  },
  // History Tab
  historyItem: {
    borderRadius: 12,
    padding: 16,
    borderWidth: 1,
    marginBottom: 12,
  },
  historyItemContent: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
  },
  historyIconContainer: {
    width: 40,
    height: 40,
    borderRadius: 20,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(16, 185, 129, 0.1)",
  },
  historyTime: {
    fontSize: 14,
    fontWeight: "600",
    marginBottom: 2,
  },
  historyDetails: {
    fontSize: 13,
  },
  historyStatus: {
    fontSize: 12,
  },
  // Setup Tab
  setupCard: {
    borderRadius: 12,
    padding: 16,
    borderWidth: 1,
    gap: 12,
  },
  setupHeader: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 12,
  },
  setupTitle: {
    fontSize: 16,
    fontWeight: "700",
    marginBottom: 2,
  },
  setupDescription: {
    fontSize: 13,
  },
  setupSteps: {
    fontSize: 14,
    fontWeight: "700",
    marginTop: 4,
  },
  stepsList: {
    gap: 12,
    marginTop: 8,
  },
  step: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 12,
  },
  stepNumber: {
    fontSize: 16,
    fontWeight: "700",
    minWidth: 28,
  },
  stepText: {
    fontSize: 13,
    lineHeight: 18,
    flex: 1,
  },
  setupButton: {
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 8,
    alignItems: "center",
    marginTop: 8,
  },
  setupButtonText: {
    fontSize: 15,
    fontWeight: "700",
  },
  // Tips Tab
  tipCard: {
    borderRadius: 12,
    padding: 16,
    borderWidth: 1,
    marginBottom: 12,
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 12,
  },
  tipIconContainer: {
    width: 44,
    height: 44,
    borderRadius: 22,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "rgba(59, 130, 246, 0.1)",
  },
  tipTitle: {
    fontSize: 15,
    fontWeight: "700",
    marginBottom: 2,
  },
  tipDescription: {
    fontSize: 13,
    lineHeight: 18,
  },
});
