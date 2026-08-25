import Constants from 'expo-constants';

const extra = Constants.expoConfig?.extra ?? {};

export const APP_VERSION = String(Constants.expoConfig?.version ?? extra.appVersion ?? '1.0.0');
export const BUILD_NUMBER = String(
  extra.buildNumber ?? Constants.nativeBuildVersion ?? '1'
);
export const BUILD_TAG = String(extra.buildTag ?? '');
export const APP_ENVIRONMENT = String(extra.environment ?? 'production');
export const STELLAR_NETWORK = String(extra.stellarNetwork ?? 'mainnet');

/**
 * Whether this build is a development or internal (non-production) build.
 *
 * Debug screens (deep-link-debug, notification-debug, qa-smoke-checklist,
 * offline-queue-inspector) expose internal state and allow arbitrary deep
 * links to be injected, so they must only be registered and reachable in
 * development or internal builds. Production builds gate them out entirely.
 *
 * A build is considered "debug" when it is not a production build. This covers
 * local development (`dev`), staging, shared testnet, and branch previews.
 */
export const IS_DEBUG_BUILD = APP_ENVIRONMENT !== 'production';
export const BUILD_METADATA = `${APP_VERSION}+${BUILD_NUMBER}`;
export const API_URL = String(
  extra.apiUrl ?? process.env['EXPO_PUBLIC_API_URL'] ?? 'http://localhost:3000'
);
