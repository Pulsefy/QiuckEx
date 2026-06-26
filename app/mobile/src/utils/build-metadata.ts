import { APP_VERSION, BUILD_NUMBER, APP_ENVIRONMENT, STELLAR_NETWORK, BUILD_TAG, BUILD_METADATA } from '../config/build';

export interface BuildMetadata {
  appVersion: string;
  buildNumber: string;
  gitBranch: string;
  gitCommit: string;
  environment: string;
  network: string;
  buildMetadata: string;
}

/**
 * Get build metadata for display in settings
 * Git branch and commit are extracted from BUILD_TAG if available
 */
export function getBuildMetadata(): BuildMetadata {
  // Extract branch and commit from BUILD_TAG (format: branch-commithash)
  // or use fallback values
  let gitBranch = 'Unknown';
  let gitCommit = 'Unknown';

  if (BUILD_TAG) {
    const parts = BUILD_TAG.split('-');
    if (parts.length >= 2) {
      gitBranch = parts.slice(0, -1).join('-');
      gitCommit = parts[parts.length - 1];
    } else {
      gitBranch = BUILD_TAG;
    }
  }

  return {
    appVersion: APP_VERSION,
    buildNumber: BUILD_NUMBER,
    gitBranch,
    gitCommit,
    environment: APP_ENVIRONMENT,
    network: STELLAR_NETWORK,
    buildMetadata: BUILD_METADATA,
  };
}

/**
 * Format environment for display
 */
export function formatEnvironment(env: string): string {
  switch (env) {
    case 'production':
      return 'Production';
    case 'staging':
      return 'Staging';
    case 'dev':
      return 'Development';
    default:
      return env.charAt(0).toUpperCase() + env.slice(1);
  }
}

/**
 * Format network for display
 */
export function formatNetwork(network: string): string {
  return network.charAt(0).toUpperCase() + network.slice(1);
}

/**
 * Get a human-readable label for a metadata field
 */
export function getMetadataLabel(key: keyof BuildMetadata): string {
  const labels: Record<keyof BuildMetadata, string> = {
    appVersion: 'App Version',
    buildNumber: 'Build Number',
    gitBranch: 'Git Branch',
    gitCommit: 'Git Commit',
    environment: 'Environment',
    network: 'Network',
    buildMetadata: 'Build Metadata',
  };
  return labels[key];
}
