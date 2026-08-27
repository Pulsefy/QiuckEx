import { useRouter } from 'expo-router';
import React, { useEffect, useState } from 'react';
import {
  ScrollView,
  StyleSheet,
  Text,
  View,
  Pressable,
  Switch,
  SafeAreaView,
} from 'react-native';
import { useTheme } from '../src/theme/ThemeContext';
import { CrashReportingService } from '@/services/CrashReportingService';

export default function CrashReportingConsentScreen() {
  const router = useRouter();
  const { theme } = useTheme();
  const [crashConsent, setCrashConsent] = useState(false);
  const [analyticsConsent, setAnalyticsConsent] = useState(false);

  useEffect(() => {
    const loadConsent = async () => {
      const consent = await CrashReportingService.getConsent();
      setCrashConsent(consent.crashReportingConsent);
      setAnalyticsConsent(consent.analyticsConsent);
    };
    loadConsent();
  }, []);

  const handleAccept = async () => {
    await CrashReportingService.setConsent({
      crashReportingConsent: crashConsent,
      analyticsConsent: analyticsConsent,
    });
    router.replace('/');
  };

  const handleDecline = async () => {
    await CrashReportingService.setConsent({
      crashReportingConsent: false,
      analyticsConsent: false,
    });
    router.replace('/');
  };

  const styles = themedStyles({
    background: theme.background,
    textPrimary: theme.textPrimary,
    textSecondary: theme.textSecondary,
    buttonPrimaryBg: theme.buttonPrimaryBg,
    buttonPrimaryText: theme.buttonPrimaryText,
    borderColor: theme.borderColor,
  });

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <ScrollView contentContainerStyle={styles.scrollContent} showsVerticalScrollIndicator={false}>
        <Text style={[styles.title, { color: theme.textPrimary }]}>Help Us Improve</Text>

        <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
          QuickEx would like to collect data to improve your experience and fix crashes.
        </Text>

        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>Crash Reporting</Text>
          <Text style={[styles.description, { color: theme.textSecondary }]}>
            Automatically send crash reports and error logs to help us fix issues faster.
          </Text>
          <View style={[styles.toggleRow, { borderBottomColor: theme.borderColor }]}>
            <Text style={[styles.toggleLabel, { color: theme.textPrimary }]}>Enable Crash Reporting</Text>
            <Switch
              value={crashConsent}
              onValueChange={setCrashConsent}
              trackColor={{ false: theme.borderColor, true: theme.buttonPrimaryBg }}
              thumbColor={theme.textPrimary}
            />
          </View>
        </View>

        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>Analytics</Text>
          <Text style={[styles.description, { color: theme.textSecondary }]}>
            Share anonymous usage data to help us understand which features are most valuable.
          </Text>
          <View style={[styles.toggleRow, { borderBottomColor: theme.borderColor }]}>
            <Text style={[styles.toggleLabel, { color: theme.textPrimary }]}>Enable Analytics</Text>
            <Switch
              value={analyticsConsent}
              onValueChange={setAnalyticsConsent}
              trackColor={{ false: theme.borderColor, true: theme.buttonPrimaryBg }}
              thumbColor={theme.textPrimary}
            />
          </View>
        </View>

        <View style={styles.section}>
          <Text style={[styles.sectionTitle, { color: theme.textPrimary }]}>Privacy Notice</Text>
          <Text style={[styles.description, { color: theme.textSecondary }]}>
            • No personal data like wallet addresses or transaction details are collected{'\n'}
            • You can change these settings anytime in Settings → Privacy{'\n'}
            • All data is encrypted and stored securely{'\n'}
            • You can opt out and delete all data at any time
          </Text>
        </View>

        <View style={styles.buttonContainer}>
          <Pressable
            style={[styles.acceptButton, { backgroundColor: theme.buttonPrimaryBg }]}
            onPress={handleAccept}
            android_ripple={{ color: 'rgba(0,0,0,0.2)' }}
          >
            <Text style={[styles.acceptButtonText, { color: theme.buttonPrimaryText }]}>Accept</Text>
          </Pressable>

          <Pressable
            style={[styles.declineButton, { borderColor: theme.borderColor }]}
            onPress={handleDecline}
            android_ripple={{ color: 'rgba(0,0,0,0.1)' }}
          >
            <Text style={[styles.declineButtonText, { color: theme.textSecondary }]}>Decline</Text>
          </Pressable>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

function themedStyles(theme: {
  background: string;
  textPrimary: string;
  textSecondary: string;
  buttonPrimaryBg: string;
  buttonPrimaryText: string;
  borderColor: string;
}) {
  return StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: theme.background,
    },
    scrollContent: {
      padding: 20,
      paddingBottom: 40,
    },
    title: {
      fontSize: 28,
      fontWeight: '700',
      marginBottom: 12,
    },
    subtitle: {
      fontSize: 16,
      lineHeight: 24,
      marginBottom: 32,
    },
    section: {
      marginBottom: 28,
    },
    sectionTitle: {
      fontSize: 16,
      fontWeight: '600',
      marginBottom: 8,
    },
    description: {
      fontSize: 14,
      lineHeight: 20,
      marginBottom: 16,
    },
    toggleRow: {
      flexDirection: 'row',
      justifyContent: 'space-between',
      alignItems: 'center',
      paddingVertical: 12,
      borderBottomWidth: 1,
    },
    toggleLabel: {
      fontSize: 15,
      fontWeight: '500',
    },
    buttonContainer: {
      gap: 12,
      marginTop: 20,
    },
    acceptButton: {
      paddingVertical: 14,
      paddingHorizontal: 20,
      borderRadius: 10,
      alignItems: 'center',
    },
    acceptButtonText: {
      fontSize: 16,
      fontWeight: '600',
    },
    declineButton: {
      paddingVertical: 14,
      paddingHorizontal: 20,
      borderRadius: 10,
      alignItems: 'center',
      borderWidth: 1.5,
    },
    declineButtonText: {
      fontSize: 16,
      fontWeight: '600',
    },
  });
}
