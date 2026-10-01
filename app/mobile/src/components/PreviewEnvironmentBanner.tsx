import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { Ionicons } from '@expo/vector-icons';
import * as buildMetadata from '../utils/build-metadata';
import { useEnvironmentOptional } from '../../contexts/EnvironmentContext';

/**
 * FE-38 — Contributor preview-environment banner.
 *
 * Shows a persistent banner in every non-production build (preview / testnet /
 * staging / development) so contributors always know which environment they are
 * looking at. The environment name, network and branch are read from the
 * dynamic runtime config bootstrap / active environment (falling back to
 * build/environment config `getBuildMetadata`), so screenshots, bug reports and
 * support threads always carry the right context, and the banner updates
 * whenever the environment changes.
 *
 * Renders nothing in production, so production users never see preview-only
 * messaging.
 */
export function PreviewEnvironmentBanner() {
  const insets = useSafeAreaInsets();
  const envContext = useEnvironmentOptional();
  const meta = buildMetadata.getBuildMetadata();

  const activeEnv = envContext ? envContext.currentId : meta.environment;
  const activeNetwork = envContext?.networkConfig?.network || meta.network;
  const activeBranch =
    envContext?.previewMetadata?.branch ||
    envContext?.previewScope ||
    (meta.gitBranch && meta.gitBranch !== 'Unknown' ? meta.gitBranch : null);

  // Production builds never show preview messaging.
  if (activeEnv === 'production') {
    return null;
  }

  const summary = `${buildMetadata.formatEnvironment(activeEnv)} · ${buildMetadata.formatNetwork(
    activeNetwork,
  )}`;
  const label = activeBranch ? `${summary} · ${activeBranch}` : summary;

  return (
    <View
      testID="preview-environment-banner"
      accessibilityLabel={`Preview environment: ${label}`}
      style={[styles.container, { paddingTop: insets.top }]}
    >
      <View style={styles.content}>
        <Ionicons name="flask" size={16} color={TEXT_COLOR} />
        <Text testID="preview-environment-banner-text" style={styles.text}>
          {label}
        </Text>
      </View>
    </View>
  );
}

// Fixed, high-contrast "preview" colours (amber) so the banner is unmistakable
// regardless of the active theme — it is a build indicator, not themed chrome.
const BACKGROUND_COLOR = '#f59e0b';
const TEXT_COLOR = '#1f2937';

const styles = StyleSheet.create({
  container: {
    width: '100%',
    backgroundColor: BACKGROUND_COLOR,
    zIndex: 1000,
    elevation: 10,
  },
  content: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 6,
    paddingHorizontal: 16,
    gap: 6,
  },
  text: {
    color: TEXT_COLOR,
    fontSize: 13,
    fontWeight: '700',
  },
});
