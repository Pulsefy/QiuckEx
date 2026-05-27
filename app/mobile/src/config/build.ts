import Constants from 'expo-constants';

const extra = Constants.expoConfig?.extra ?? {};

export const APP_VERSION = String(Constants.expoConfig?.version ?? extra.appVersion ?? '1.0.0');
export const BUILD_NUMBER = String(
  extra.buildNumber ?? Constants.nativeBuildVersion ?? '1'
);
export const BUILD_TAG = String(extra.buildTag ?? '');
export const APP_ENVIRONMENT = String(extra.environment ?? 'production');
export const STELLAR_NETWORK = String(extra.stellarNetwork ?? 'mainnet');
export const BUILD_METADATA = `${APP_VERSION}+${BUILD_NUMBER}`;
export const API_URL = String(
  extra.apiUrl ?? process.env['EXPO_PUBLIC_API_URL'] ?? 'http://localhost:3000'
);
