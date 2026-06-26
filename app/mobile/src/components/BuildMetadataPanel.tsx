import React, { useState } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Alert,
} from 'react-native';
import { useTheme } from '../hooks/useTheme';
import { themeTokens } from '../theme/tokens';
import { 
  getBuildMetadata, 
  formatEnvironment, 
  formatNetwork, 
  getMetadataLabel,
  type BuildMetadata 
} from '../utils/build-metadata';
import { copyToClipboard } from '../utils/clipboard';

interface CopyableMetadataRowProps {
  label: string;
  value: string;
}

/**
 * Copyable metadata row with feedback
 */
function CopyableMetadataRow({ label, value }: CopyableMetadataRowProps) {
  const { color, tokens } = useTheme();
  const [justCopied, setJustCopied] = useState(false);

  const handleCopy = async () => {
    const success = await copyToClipboard(value);
    if (success) {
      setJustCopied(true);
      // Reset after 2 seconds
      setTimeout(() => setJustCopied(false), 2000);
    } else {
      Alert.alert('Error', 'Failed to copy to clipboard');
    }
  };

  const styles = getMetadataStyles({ color, tokens });

  return (
    <TouchableOpacity
      style={styles.row}
      onPress={handleCopy}
      activeOpacity={0.7}
    >
      <Text style={[styles.label, { color: color(tokens.text.primary) }]}>
        {label}
      </Text>
      <View style={styles.right}>
        <Text
          style={[
            styles.value,
            {
              color: justCopied ? color(tokens.action.primary) : color(tokens.text.secondary),
            },
          ]}
          numberOfLines={1}
        >
          {justCopied ? '✓ Copied' : value}
        </Text>
        <Text
          style={[
            styles.copyIcon,
            {
              color: justCopied ? color(tokens.action.primary) : color(tokens.text.tertiary),
            },
          ]}
        >
          {justCopied ? '✓' : '📋'}
        </Text>
      </View>
    </TouchableOpacity>
  );
}

/**
 * Build Metadata Panel Component
 * Displays build information including version, build number, git branch/commit,
 * environment, and network. All fields are copyable.
 */
export function BuildMetadataPanel() {
  const { color, tokens } = useTheme();
  const metadata = getBuildMetadata();
  const styles = getMetadataStyles({ color, tokens });

  const displayMetadata = {
    appVersion: metadata.appVersion,
    buildNumber: metadata.buildNumber,
    gitBranch: metadata.gitBranch,
    gitCommit: metadata.gitCommit,
    environment: formatEnvironment(metadata.environment),
    network: formatNetwork(metadata.network),
  };

  const handleCopyAll = async () => {
    const text = Object.entries(displayMetadata)
      .map(([key, value]) => `${getMetadataLabel(key as keyof BuildMetadata)}: ${value}`)
      .join('\n');

    const success = await copyToClipboard(text);
    if (success) {
      Alert.alert('Success', 'All metadata copied to clipboard');
    } else {
      Alert.alert('Error', 'Failed to copy metadata');
    }
  };

  return (
    <View>
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Build Metadata</Text>
        <Text style={styles.sectionDescription}>
          Tap any field to copy. Share this info when reporting issues.
        </Text>
      </View>

      <View style={styles.metadataContainer}>
        {Object.entries(displayMetadata).map(([key, value], index) => (
          <View key={key}>
            <CopyableMetadataRow
              label={getMetadataLabel(key as keyof BuildMetadata)}
              value={String(value)}
            />
            {index < Object.entries(displayMetadata).length - 1 && (
              <View style={[styles.divider, { backgroundColor: color(tokens.border.subtle) }]} />
            )}
          </View>
        ))}
      </View>

      <TouchableOpacity
        style={[styles.copyAllButton, { backgroundColor: color(tokens.action.primary) }]}
        onPress={handleCopyAll}
        activeOpacity={0.8}
      >
        <Text style={[styles.copyAllText, { color: color(tokens.text.inverse) }]}>
          Copy All Metadata
        </Text>
      </TouchableOpacity>
    </View>
  );
}

function getMetadataStyles({ color, tokens }: {
  color: (t: any) => string;
  tokens: typeof themeTokens;
}) {
  return StyleSheet.create({
    section: {
      marginTop: 24,
      paddingHorizontal: 20,
      marginBottom: 12,
    },
    sectionTitle: {
      fontSize: 13,
      fontWeight: '700',
      color: color(tokens.text.secondary),
      textTransform: 'uppercase',
      letterSpacing: 1,
      marginBottom: 8,
    },
    sectionDescription: {
      fontSize: 12,
      color: color(tokens.text.tertiary),
      marginTop: 4,
    },
    metadataContainer: {
      marginHorizontal: 20,
      borderRadius: 12,
      backgroundColor: color(tokens.surfaceElevated),
      overflow: 'hidden',
      borderWidth: 1,
      borderColor: color(tokens.border.subtle),
    },
    row: {
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'space-between',
      paddingVertical: 12,
      paddingHorizontal: 16,
    },
    label: {
      fontSize: 14,
      fontWeight: '500',
      flex: 1,
    },
    right: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 8,
      flex: 1,
      justifyContent: 'flex-end',
    },
    value: {
      fontSize: 13,
      maxWidth: 140,
      fontFamily: 'Courier New',
    },
    copyIcon: {
      fontSize: 14,
      fontWeight: '600',
    },
    divider: {
      height: 1,
    },
    copyAllButton: {
      marginHorizontal: 20,
      marginTop: 16,
      marginBottom: 24,
      paddingVertical: 14,
      borderRadius: 12,
      alignItems: 'center',
      justifyContent: 'center',
    },
    copyAllText: {
      fontSize: 15,
      fontWeight: '600',
    },
  });
}
