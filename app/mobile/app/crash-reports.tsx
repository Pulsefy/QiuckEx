import { useRouter } from 'expo-router';
import React, { useEffect, useState } from 'react';
import {
  ScrollView,
  StyleSheet,
  Text,
  View,
  Pressable,
  SafeAreaView,
  ActivityIndicator,
  Alert,
  Share,
} from 'react-native';
import { useTheme } from '../src/theme/ThemeContext';
import { CrashReportingService, CrashReport } from '@/services/CrashReportingService';
import { Ionicons } from '@expo/vector-icons';

export default function CrashReportsScreen() {
  const router = useRouter();
  const { theme } = useTheme();
  const [reports, setReports] = useState<CrashReport[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadCrashReports();
  }, []);

  const loadCrashReports = async () => {
    setLoading(true);
    const data = await CrashReportingService.getCrashReports();
    setReports(data);
    setLoading(false);
  };

  const handleExportReport = async (reportId: string) => {
    const data = await CrashReportingService.exportCrashReport(reportId);
    if (data) {
      try {
        await Share.share({
          message: data,
          title: `Crash Report ${reportId}`,
        });
      } catch (error) {
        Alert.alert('Error', 'Failed to share crash report');
      }
    }
  };

  const handleExportAll = async () => {
    const data = await CrashReportingService.exportAllCrashReports();
    if (data) {
      try {
        await Share.share({
          message: data,
          title: 'All Crash Reports',
        });
      } catch (error) {
        Alert.alert('Error', 'Failed to share crash reports');
      }
    }
  };

  const handleClearReports = () => {
    Alert.alert(
      'Clear Crash Reports',
      'Are you sure you want to delete all crash reports?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            await CrashReportingService.clearCrashReports();
            setReports([]);
          },
        },
      ],
    );
  };

  const styles = themedStyles({
    background: theme.background,
    textPrimary: theme.textPrimary,
    textSecondary: theme.textSecondary,
    textTertiary: theme.textTertiary,
    buttonPrimaryBg: theme.buttonPrimaryBg,
    buttonPrimaryText: theme.buttonPrimaryText,
    borderColor: theme.borderColor,
    successColor: '#10b981',
    errorColor: '#ef4444',
  });

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <View style={styles.header}>
        <Pressable onPress={() => router.back()} hitSlop={8}>
          <Ionicons name="chevron-back" size={24} color={theme.textPrimary} />
        </Pressable>
        <Text style={[styles.headerTitle, { color: theme.textPrimary }]}>Crash Reports</Text>
        <View style={{ width: 24 }} />
      </View>

      {loading ? (
        <View style={styles.centerContainer}>
          <ActivityIndicator size="large" color={theme.buttonPrimaryBg} />
        </View>
      ) : reports.length === 0 ? (
        <View style={styles.emptyContainer}>
          <Ionicons name="checkmark-circle" size={48} color={theme.textTertiary} />
          <Text style={[styles.emptyTitle, { color: theme.textPrimary }]}>No Crash Reports</Text>
          <Text style={[styles.emptyText, { color: theme.textSecondary }]}>
            Great! No crashes have been recorded yet.
          </Text>
        </View>
      ) : (
        <ScrollView style={styles.content} showsVerticalScrollIndicator={false}>
          <View style={styles.reportsList}>
            {reports.map((report) => (
              <View key={report.id} style={[styles.reportCard, { borderColor: theme.borderColor }]}>
                <View style={styles.reportHeader}>
                  <View>
                    <Text style={[styles.reportError, { color: theme.textPrimary }]}>
                      {report.error.substring(0, 50)}...
                    </Text>
                    <Text style={[styles.reportTime, { color: theme.textSecondary }]}>
                      {new Date(report.timestamp).toLocaleString()}
                    </Text>
                  </View>
                  <Ionicons name="alert-circle" size={24} color="#ef4444" />
                </View>

                <View style={styles.reportDetails}>
                  <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>
                    Breadcrumbs: {report.breadcrumbs.length}
                  </Text>
                  {report.userContext && (
                    <Text style={[styles.detailLabel, { color: theme.textSecondary }]}>
                      User: {report.userContext.username}
                    </Text>
                  )}
                </View>

                <Pressable
                  style={[styles.exportButton, { backgroundColor: theme.buttonPrimaryBg }]}
                  onPress={() => handleExportReport(report.id)}
                  android_ripple={{ color: 'rgba(0,0,0,0.2)' }}
                >
                  <Ionicons name="share-social" size={16} color={theme.buttonPrimaryText} />
                  <Text style={[styles.exportButtonText, { color: theme.buttonPrimaryText }]}>
                    Export
                  </Text>
                </Pressable>
              </View>
            ))}
          </View>

          <View style={styles.actionsContainer}>
            <Pressable
              style={[styles.actionButton, { backgroundColor: theme.buttonPrimaryBg }]}
              onPress={handleExportAll}
              android_ripple={{ color: 'rgba(0,0,0,0.2)' }}
            >
              <Ionicons name="download" size={18} color={theme.buttonPrimaryText} />
              <Text style={[styles.actionButtonText, { color: theme.buttonPrimaryText }]}>
                Export All
              </Text>
            </Pressable>

            <Pressable
              style={[styles.actionButton, { backgroundColor: '#ef4444' }]}
              onPress={handleClearReports}
              android_ripple={{ color: 'rgba(0,0,0,0.2)' }}
            >
              <Ionicons name="trash" size={18} color="white" />
              <Text style={[styles.actionButtonText, { color: 'white' }]}>Clear All</Text>
            </Pressable>
          </View>
        </ScrollView>
      )}
    </SafeAreaView>
  );
}

function themedStyles(theme: {
  background: string;
  textPrimary: string;
  textSecondary: string;
  textTertiary: string;
  buttonPrimaryBg: string;
  buttonPrimaryText: string;
  borderColor: string;
  successColor: string;
  errorColor: string;
}) {
  return StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: theme.background,
    },
    header: {
      flexDirection: 'row',
      justifyContent: 'space-between',
      alignItems: 'center',
      paddingHorizontal: 16,
      paddingVertical: 12,
      borderBottomWidth: 1,
      borderBottomColor: theme.borderColor,
    },
    headerTitle: {
      fontSize: 18,
      fontWeight: '600',
    },
    centerContainer: {
      flex: 1,
      justifyContent: 'center',
      alignItems: 'center',
    },
    emptyContainer: {
      flex: 1,
      justifyContent: 'center',
      alignItems: 'center',
      paddingHorizontal: 20,
    },
    emptyTitle: {
      fontSize: 18,
      fontWeight: '600',
      marginTop: 16,
      marginBottom: 8,
    },
    emptyText: {
      fontSize: 14,
      textAlign: 'center',
    },
    content: {
      flex: 1,
      padding: 16,
    },
    reportsList: {
      gap: 12,
    },
    reportCard: {
      borderWidth: 1,
      borderRadius: 12,
      padding: 12,
      gap: 12,
    },
    reportHeader: {
      flexDirection: 'row',
      justifyContent: 'space-between',
      alignItems: 'flex-start',
    },
    reportError: {
      fontSize: 14,
      fontWeight: '600',
      flex: 1,
    },
    reportTime: {
      fontSize: 12,
      marginTop: 4,
    },
    reportDetails: {
      gap: 4,
    },
    detailLabel: {
      fontSize: 12,
    },
    exportButton: {
      flexDirection: 'row',
      paddingVertical: 8,
      paddingHorizontal: 12,
      borderRadius: 6,
      alignItems: 'center',
      justifyContent: 'center',
      gap: 6,
    },
    exportButtonText: {
      fontSize: 13,
      fontWeight: '500',
    },
    actionsContainer: {
      gap: 12,
      marginTop: 16,
      marginBottom: 20,
    },
    actionButton: {
      flexDirection: 'row',
      paddingVertical: 12,
      paddingHorizontal: 16,
      borderRadius: 10,
      alignItems: 'center',
      justifyContent: 'center',
      gap: 8,
    },
    actionButtonText: {
      fontSize: 15,
      fontWeight: '600',
    },
  });
}
