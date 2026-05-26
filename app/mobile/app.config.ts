import appJson from './app.json';

const defaultEnvironment = process.env.CI ? 'production' : 'dev';
const appEnv = process.env.APP_ENV ?? defaultEnvironment;
const stellarNetwork = process.env.STELLAR_NETWORK ?? (appEnv === 'production' ? 'mainnet' : 'testnet');
const buildNumber = process.env.BUILD_NUMBER ?? process.env.GITHUB_RUN_NUMBER ?? '1';
const androidVersionCode = Number(process.env.ANDROID_VERSION_CODE ?? buildNumber);
const buildTag = process.env.GIT_TAG ?? process.env.GITHUB_REF_NAME ?? '';

export default ({ config }: { config: any }) => ({
  ...appJson,
  expo: {
    ...appJson.expo,
    extra: {
      ...appJson.expo.extra,
      environment: appEnv,
      stellarNetwork,
      buildNumber,
      buildTag,
      appVersion: appJson.expo.version,
    },
    ios: {
      ...appJson.expo.ios,
      buildNumber,
    },
    android: {
      ...appJson.expo.android,
      versionCode: androidVersionCode,
    },
  },
});
