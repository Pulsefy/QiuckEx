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
} from 'react-native';
import { useTheme } from '../src/theme/ThemeContext';
import { AppUpdateService, UpdateHistory } from '@/services/AppUpdateService';
import { Ionicons } from '@expo/vector-icons';

export default function UpdateHistoryScreen() {
  const router = useRouter();
  const { theme } = useTheme();
  const [history, setHistory] = useState<UpdateHistory[]>([]);
  const [currentVersion, setCurrentVersion] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const historyData = await AppUpdateService.getUpdateHistory();
      setHistory(historyData);
      setCurrentVersion(AppUpdateService.getCurrentVersion());
    } catch (error) {
      console.error('Failed to load update history:', error);
    } finally {
      setLoading(false);
    }
  };

  const styles = themedStyles({
    background: theme.background,
    textPrimary: theme.textPrimary,
    textSecondary: theme.textSecondary,
    textTertiary: theme.textTertiary,
    borderColor: theme.borderColor,
    buttonPrimaryBg: theme.buttonPrimaryBg,
  });

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: theme.background }]}>
      <View style={styles.header}>
        <Pressable onPress={() => router.back()} hitSlop={8}>
          <Ionicons name="chevron-back" size={24} color={theme.textPrimary} />
        </Pressable>
        <Text style={[styles.headerTitle, { color: theme.textPrimary }]}>Update History</Text>
        <View style={{ width: 24 }} />
      </View>

      {loading ? (
        <View style={styles.centerContainer}>
          <ActivityIndicator size="large" color={theme.buttonPrimaryBg} />
        </View>
      ) : (
        <ScrollView style={styles.content} showsVerticalScrollIndicator={false}>
          <View style={styles.currentVersionContainer}>
            <View style={[styles.versionBadge, { backgroundColor: theme.buttonPrimaryBg }]}>
              <Ionicons name="checkmark-circle" size={24} color="white" />
            </View>
            <View style={styles.versionInfo}>
              <Text style={[styles.currentVersionLabel, { color: theme.textSecondary }]}>
                Current Version
              </Text>
              <Text style={[styles.currentVersion, { color: theme.textPrimary }]}>
                {currentVersion}
              </Text>
              <Text style={[styles.currentVersionDate, { color: theme.textTertiary }]}>
                Installed {new Date().toLocaleDateString()}
              </Text>
            </View>
          </View>

          <View style={styles.divider} />

          <Text style={[styles.sectionTitle, { color: theme.textSecondary }]}>
            Previous Updates
          </Text>

          {history.length === 0 ? (
            <View style={styles.emptyContainer}>
              <Text style={[styles.emptyText, { color: theme.textSecondary }]}>
                No previous updates recorded
              </Text>
            </View>
          ) : (
            <View style={styles.historyList}>
              {history
                .sort((a, b) => new Date(b.installedDate).getTime() - new Date(a.installedDate).getTime())
                .map((item, index) => (
                  <View key={index} style={[styles.historyItem, { borderColor: theme.borderColor }]}>
                    <View style={styles.historyHeader}>
                      <Text style={[styles.historyVersion, { color: theme.textPrimary }]}>
                        Version {item.version}
                      </Text>
                      <Text style={[styles.historyDate, { color: theme.textSecondary }]}>
                        {new Date(item.installedDate).toLocaleDateString()}
                      </Text>
                    </View>

                    {item.releaseNotes.length > 0 && (
                      <View style={styles.releaseNotesContainer}>
                        {item.releaseNotes.map((note, noteIndex) => (
                          <Text
                            key={noteIndex}
                            style={[styles.releaseNote, { color: theme.textSecondary }]}
                          >
                            • {note}
                          </Text>
                        ))}
                      </View>
                    )}
                  </View>
                ))}
            </View>
          )}
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
  borderColor: string;
  buttonPrimaryBg: string;
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
    content: {
      flex: 1,
      padding: 16,
    },
    currentVersionContainer: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 16,
      paddingVertical: 16,
      paddingHorizontal: 12,
      borderRadius: 12,
      borderWidth: 1,
      borderColor: theme.borderColor,
    },
    versionBadge: {
      width: 56,
      height: 56,
      borderRadius: 28,
      justifyContent: 'center',
      alignItems: 'center',
    },
    versionInfo: {
      flex: 1,
    },
    currentVersionLabel: {
      fontSize: 12,
      fontWeight: '500',
      marginBottom: 4,
    },
    currentVersion: {
      fontSize: 18,
      fontWeight: '700',
      marginBottom: 2,
    },
    currentVersionDate: {
      fontSize: 12,
    },
    divider: {
      height: 1,
      backgroundColor: theme.borderColor,
      marginVertical: 16,
    },
    sectionTitle: {
      fontSize: 13,
      fontWeight: '600',
      textTransform: 'uppercase',
      letterSpacing: 0.5,
      marginBottom: 12,
    },
    emptyContainer: {
      paddingVertical: 32,
      alignItems: 'center',
    },
    emptyText: {
      fontSize: 14,
    },
    historyList: {
      gap: 12,
    },
    historyItem: {
      borderWidth: 1,
      borderRadius: 12,
      padding: 12,
      gap: 8,
    },
    historyHeader: {
      flexDirection: 'row',
      justifyContent: 'space-between',
      alignItems: 'center',
    },
    historyVersion: {
      fontSize: 15,
      fontWeight: '600',
    },
    historyDate: {
      fontSize: 12,
    },
    releaseNotesContainer: {
      gap: 4,
      marginTop: 8,
      paddingTop: 8,
      borderTopWidth: 1,
      borderTopColor: theme.borderColor,
    },
    releaseNote: {
      fontSize: 13,
      lineHeight: 18,
    },
  });
}
