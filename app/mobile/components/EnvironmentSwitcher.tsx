import React, { useEffect } from 'react';
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import { useEnvironment } from '../contexts/EnvironmentContext';
import { useTheme } from '../src/theme/ThemeContext';

export function EnvironmentSwitcher() {
  const { theme } = useTheme();
  const {
    currentId,
    available,
    switchEnvironment,
    resetToDefault,
    metadata,
    compatibility,
    isFetchingMetadata,
    fetchMetadata,
  } = useEnvironment();

  useEffect(() => {
    if (currentId !== 'production') {
      fetchMetadata();
    }
  }, [currentId, fetchMetadata]);

  return (
    <View
      style={[
        styles.container,
        { backgroundColor: theme.surface, borderColor: theme.border },
      ]}
    >
      <Text style={[styles.title, { color: theme.textPrimary }]}>
        Environment
      </Text>
      <Text style={[styles.helper, { color: theme.textMuted }]}>
        Switch between backend environments for testing.
      </Text>

      <View style={styles.environmentList}>
        {available.map((env) => {
          const isActive = env.id === currentId;
          return (
            <Pressable
              key={env.id}
              testID={`switch-${env.id}`}
              style={[
                styles.environmentItem,
                {
                  backgroundColor: isActive
                    ? theme.chipActiveBg
                    : theme.background,
                  borderColor: isActive
                    ? theme.buttonPrimaryBg
                    : theme.borderLight,
                },
              ]}
              onPress={() => {
                switchEnvironment(env.id);
              }}
            >
              <View style={styles.environmentInfo}>
                <Text
                  style={[
                    styles.environmentLabel,
                    {
                      color: isActive
                        ? theme.chipActiveText
                        : theme.textPrimary,
                    },
                  ]}
                >
                  {env.label}
                </Text>
                <Text
                  style={[
                    styles.environmentUrl,
                    { color: theme.textMuted },
                  ]}
                >
                  {env.apiUrl}
                </Text>
                {env.buildTag ? (
                  <View
                    style={[
                      styles.tag,
                      { backgroundColor: theme.chipBg },
                    ]}
                  >
                    <Text
                      style={[
                        styles.tagText,
                        { color: theme.textMuted },
                      ]}
                    >
                      {env.buildTag}
                    </Text>
                  </View>
                ) : null}
              </View>
              {isActive ? (
                <View
                  style={[
                    styles.activeDot,
                    { backgroundColor: theme.status.success },
                  ]}
                />
              ) : null}
            </Pressable>
          );
        })}
      </View>

      {currentId !== 'production' ? (
        <View
          style={[
            styles.metadataCard,
            {
              backgroundColor: theme.surfaceElevated,
              borderColor: theme.borderLight,
            },
          ]}
        >
          {isFetchingMetadata ? (
            <View style={styles.loadingRow}>
              <ActivityIndicator size="small" color={theme.textMuted} />
              <Text style={[styles.metadataText, { color: theme.textMuted }]}>
                Fetching backend metadata...
              </Text>
            </View>
          ) : null}

          {metadata ? (
            <View style={styles.metadataRow}>
              <Text style={[styles.metadataLabel, { color: theme.textSecondary }]}>
                Backend version:
              </Text>
              <Text style={[styles.metadataValue, { color: theme.textPrimary }]}>
                {metadata.appVersion}
              </Text>
            </View>
          ) : null}

          {compatibility ? (
            <View
              style={[
                styles.compatibilityBadge,
                {
                  backgroundColor: compatibility.compatible
                    ? theme.status.successBg
                    : theme.status.errorBg,
                },
              ]}
            >
              <Text
                style={[
                  styles.compatibilityText,
                  {
                    color: compatibility.compatible
                      ? theme.status.success
                      : theme.status.error,
                  },
                ]}
              >
                {compatibility.compatible
                  ? 'Compatible'
                  : `Warning: ${compatibility.reason}`}
              </Text>
            </View>
          ) : null}

          <Pressable
            style={[
              styles.fetchButton,
              { borderColor: theme.buttonSecondaryBorder },
            ]}
            onPress={fetchMetadata}
          >
            <Text
              style={[
                styles.fetchButtonText,
                { color: theme.textPrimary },
              ]}
            >
              Check Compatibility
            </Text>
          </Pressable>
        </View>
      ) : null}

      <Pressable
        testID="reset-environment"
        style={[
          styles.resetButton,
          { borderColor: theme.status.error },
        ]}
        onPress={resetToDefault}
      >
        <Text
          style={[styles.resetButtonText, { color: theme.status.error }]}
        >
          Reset to Default ({ENVIRONMENT_LABELS['production']})
        </Text>
      </Pressable>
    </View>
  );
}

const ENVIRONMENT_LABELS: Record<string, string> = {
  production: 'Production',
  staging: 'Staging',
  testnet: 'Shared Testnet',
  'branch-preview': 'Branch Preview',
};

const styles = StyleSheet.create({
  container: {
    borderRadius: 18,
    padding: 18,
    borderWidth: 1,
    gap: 14,
  },
  title: {
    fontSize: 18,
    fontWeight: '700',
  },
  helper: {
    fontSize: 13,
    lineHeight: 18,
  },
  environmentList: {
    gap: 8,
  },
  environmentItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    borderWidth: 1,
    borderRadius: 14,
    padding: 14,
  },
  environmentInfo: {
    flex: 1,
    gap: 4,
  },
  environmentLabel: {
    fontSize: 15,
    fontWeight: '700',
  },
  environmentUrl: {
    fontSize: 12,
  },
  tag: {
    alignSelf: 'flex-start',
    borderRadius: 6,
    paddingHorizontal: 8,
    paddingVertical: 2,
  },
  tagText: {
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 0.5,
  },
  activeDot: {
    width: 10,
    height: 10,
    borderRadius: 5,
    marginLeft: 8,
  },
  metadataCard: {
    borderWidth: 1,
    borderRadius: 14,
    padding: 14,
    gap: 8,
  },
  loadingRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  metadataRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  metadataLabel: {
    fontSize: 13,
    fontWeight: '600',
  },
  metadataValue: {
    fontSize: 13,
    fontWeight: '700',
  },
  compatibilityBadge: {
    borderRadius: 8,
    paddingVertical: 8,
    paddingHorizontal: 12,
  },
  compatibilityText: {
    fontSize: 13,
    fontWeight: '600',
  },
  fetchButton: {
    borderWidth: 1,
    borderRadius: 10,
    paddingVertical: 10,
    paddingHorizontal: 14,
    alignItems: 'center',
  },
  fetchButtonText: {
    fontSize: 13,
    fontWeight: '700',
  },
  resetButton: {
    borderWidth: 1,
    borderRadius: 14,
    paddingVertical: 12,
    paddingHorizontal: 16,
    alignItems: 'center',
  },
  resetButtonText: {
    fontSize: 14,
    fontWeight: '700',
  },
});
