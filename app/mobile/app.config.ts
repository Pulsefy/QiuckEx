import appJson from './app.json';

const defaultEnvironment = process.env.CI ? 'production' : 'dev';
const appEnv = process.env.APP_ENV ?? defaultEnvironment;
const stellarNetwork = process.env.STELLAR_NETWORK ?? (appEnv === 'production' ? 'mainnet' : 'testnet');
const buildNumber = process.env.BUILD_NUMBER ?? process.env.GITHUB_RUN_NUMBER ?? '1';
const androidVersionCode = Number(process.env.ANDROID_VERSION_CODE ?? buildNumber);
const buildTag = process.env.GIT_TAG ?? process.env.GITHUB_REF_NAME ?? '';

function appName(env: string): string {
  switch (env) {
    case 'production':
      return 'QuickEx';
    case 'staging':
      return 'QuickEx Staging';
    default:
      return 'QuickEx Dev';
  }
}

function bundleIdentifier(env: string): string {
  switch (env) {
    case 'production':
      return 'to.quickex.app';
    case 'staging':
      return 'to.quickex.app.staging';
    default:
      return 'to.quickex.app.dev';
  }
}

function androidPackage(env: string): string {
  switch (env) {
    case 'production':
      return 'to.quickex.app';
    case 'staging':
      return 'to.quickex.app.staging';
    default:
      return 'to.quickex.app.dev';
  }
}

function apiUrl(env: string): string {
  switch (env) {
    case 'production':
      return 'https://api.quickex.to';
    case 'staging':
      return 'https://staging-api.quickex.to';
    default:
      return process.env.EXPO_PUBLIC_API_URL ?? 'http://localhost:3000';
  }
}

export default ({ config }: { config: any }) => {
  const expo: any = appJson.expo || {};
  return {
    ...appJson,
    expo: {
      ...expo,
      name: appName(appEnv),
      extra: {
        ...(expo.extra || {}),
        apiUrl: apiUrl(appEnv),
        environment: appEnv,
        stellarNetwork,
        buildNumber,
        buildTag,
        appVersion: expo.version,
      },
      ios: {
        ...(expo.ios || {}),
        bundleIdentifier: bundleIdentifier(appEnv),
        buildNumber,
        infoPlist: {
          ...((expo.ios || {}).infoPlist || {}),
        },
      },
      android: {
        ...(expo.android || {}),
        package: androidPackage(appEnv),
        versionCode: androidVersionCode,
        intentFilters: (expo.android || {}).intentFilters,
      },
    },
  };
};
