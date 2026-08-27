import React, { useEffect, useState } from 'react';
import {
  Modal,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
  SafeAreaView,
  Linking,
  Platform,
} from 'react-native';
import { useTheme } from '../src/theme/ThemeContext';
import { AppUpdateService, UpdateCheckResult } from '@/services/AppUpdateService';
import { Ionicons } from '@expo/vector-icons';

interface AppUpdateModalProps {
  visible: boolean;
  onDismiss: () => void;
  onForceUpdate?: () => void;
}

export function AppUpdateModal({ visible, onDismiss, onForceUpdate }: AppUpdateModalProps) {
  const { theme } = useTheme();
  const [updateInfo, setUpdateInfo] = useState<UpdateCheckResult | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (visible) {
      loadUpdateInfo();
    }
  }, [visible]);

  const loadUpdateInfo = async () => {
    setLoading(true);
    try {
      const info = await AppUpdateService.checkForUpdates();
      setUpdateInfo(info);
    } catch (error) {
      console.error('Failed to check for updates:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdate = async () => {
    if (!updateInfo) return;

    try {
      await Linking.openURL(updateInfo.downloadUrl);
      if (updateInfo.isForceUpdate && onForceUpdate) {
        onForceUpdate();
      }
    } catch (error) {
      console.error('Failed to open store:', error);
    }
  };

  const handleRemindLater = async () => {
    if (!updateInfo) return;

    await AppUpdateService.skipVersion(updateInfo.latestVersion);
    onDismiss();
  };

  if (!updateInfo) {
    return null;
  }

  const styles = themedStyles({
    background: theme.background,
    textPrimary: theme.textPrimary,
    textSecondary: theme.textSecondary,
    buttonPrimaryBg: theme.buttonPrimaryBg,
    buttonPrimaryText: theme.buttonPrimaryText,
    borderColor: theme.borderColor,
    warningColor: '#f59e0b',
  });

  return (
    <Modal
      visible={visible}
      transparent
      animationType="fade"
      onRequestClose={onDismiss}
    >
      <View style={styles.overlay}>
        <View style={[styles.modal, { backgroundColor: theme.background }]}>
          <View style={styles.header}>
            <Ionicons name="gift" size={32} color={theme.buttonPrimaryBg} />
            <Text style={[styles.title, { color: theme.textPrimary }]}>
              {updateInfo.isForceUpdate ? 'Important Update' : 'Update Available'}
            </Text>
          </View>

          <View style={styles.content}>
            <Text style={[styles.versionText, { color: theme.textSecondary }]}>
              Version {updateInfo.latestVersion} is available
            </Text>

            {updateInfo.releaseNotes.length > 0 && (
              <View style={styles.notesContainer}>
                <Text style={[styles.notesTitle, { color: theme.textPrimary }]}>What's New:</Text>
                {updateInfo.releaseNotes.map((note, index) => (
                  <Text key={index} style={[styles.noteItem, { color: theme.textSecondary }]}>
                    • {note}
                  </Text>
                ))}
              </View>
            )}

            {updateInfo.isForceUpdate && (
              <View style={[styles.warningBanner, { backgroundColor: '#fef3c7' }]}>
                <Ionicons name="alert-circle" size={20} color="#f59e0b" />
                <Text style={[styles.warningText, { color: '#92400e' }]}>
                  This is a required update for security and stability.
                </Text>
              </View>
            )}
          </View>

          <View style={styles.actions}>
            <Pressable
              style={[styles.updateButton, { backgroundColor: theme.buttonPrimaryBg }]}
              onPress={handleUpdate}
              android_ripple={{ color: 'rgba(0,0,0,0.2)' }}
            >
              <Ionicons name="download" size={18} color={theme.buttonPrimaryText} />
              <Text style={[styles.updateButtonText, { color: theme.buttonPrimaryText }]}>
                Update Now
              </Text>
            </Pressable>

            {!updateInfo.isForceUpdate && (
              <Pressable
                style={[styles.laterButton, { borderColor: theme.borderColor }]}
                onPress={handleRemindLater}
                android_ripple={{ color: 'rgba(0,0,0,0.1)' }}
              >
                <Text style={[styles.laterButtonText, { color: theme.textSecondary }]}>
                  Remind Later
                </Text>
              </Pressable>
            )}
          </View>
        </View>
      </View>
    </Modal>
  );
}

function themedStyles(theme: {
  background: string;
  textPrimary: string;
  textSecondary: string;
  buttonPrimaryBg: string;
  buttonPrimaryText: string;
  borderColor: string;
  warningColor: string;
}) {
  return StyleSheet.create({
    overlay: {
      flex: 1,
      backgroundColor: 'rgba(0, 0, 0, 0.5)',
      justifyContent: 'center',
      alignItems: 'center',
      padding: 20,
    },
    modal: {
      borderRadius: 16,
      paddingTop: 24,
      paddingBottom: 20,
      paddingHorizontal: 20,
      width: '100%',
      maxHeight: '80%',
    },
    header: {
      alignItems: 'center',
      marginBottom: 20,
      gap: 12,
    },
    title: {
      fontSize: 22,
      fontWeight: '700',
      textAlign: 'center',
    },
    content: {
      gap: 16,
      maxHeight: 300,
    },
    versionText: {
      fontSize: 15,
      textAlign: 'center',
    },
    notesContainer: {
      gap: 8,
    },
    notesTitle: {
      fontSize: 14,
      fontWeight: '600',
      marginBottom: 4,
    },
    noteItem: {
      fontSize: 13,
      lineHeight: 20,
    },
    warningBanner: {
      flexDirection: 'row',
      paddingHorizontal: 12,
      paddingVertical: 10,
      borderRadius: 8,
      gap: 10,
      alignItems: 'center',
    },
    warningText: {
      fontSize: 13,
      flex: 1,
      fontWeight: '500',
    },
    actions: {
      gap: 12,
      marginTop: 20,
    },
    updateButton: {
      flexDirection: 'row',
      paddingVertical: 14,
      paddingHorizontal: 16,
      borderRadius: 10,
      alignItems: 'center',
      justifyContent: 'center',
      gap: 8,
    },
    updateButtonText: {
      fontSize: 16,
      fontWeight: '600',
    },
    laterButton: {
      paddingVertical: 12,
      paddingHorizontal: 16,
      borderRadius: 10,
      alignItems: 'center',
      borderWidth: 1.5,
    },
    laterButtonText: {
      fontSize: 15,
      fontWeight: '600',
    },
  });
}
