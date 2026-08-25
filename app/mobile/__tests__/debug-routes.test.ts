// Mock expo-constants so the build config resolves to a production build
// regardless of the jest-expo default environment.
jest.mock("expo-constants", () => ({
  __esModule: true,
  default: {
    expoConfig: {
      version: "1.0.0",
      extra: { environment: "production" },
    },
    nativeBuildVersion: "1",
  },
}));

import { resolveDeepLink } from '../utils/deep-link-routing';
import { IS_DEBUG_BUILD } from '../src/config/build';

/**
 * Debug screens (deep-link-debug, notification-debug, qa-smoke-checklist,
 * offline-queue-inspector) expose internal state and allow arbitrary deep
 * links to be injected. They must only be registered and reachable in
 * development/internal builds.
 *
 * Under a production configuration, IS_DEBUG_BUILD is false, so deep links
 * targeting debug routes must be rejected.
 */
describe('debug routes gating', () => {
  it('is not a debug build under the production configuration', () => {
    expect(IS_DEBUG_BUILD).toBe(false);
  });

  it('rejects deep links targeting debug routes in production builds', () => {
    const debugLinks = [
      'https://quickex.to/deep-link-debug',
      'quickex://deep-link-debug',
      'https://quickex.to/notification-debug',
      'https://quickex.to/qa-smoke-checklist',
      'https://quickex.to/offline-queue-inspector',
    ];

    for (const link of debugLinks) {
      const result = resolveDeepLink(link);
      expect('route' in result).toBe(false);
      expect(result).toEqual({ error: 'Unsupported or expired QuickEx link.' });
    }
  });

  it('still resolves legitimate deep links in production builds', () => {
    const result = resolveDeepLink('https://quickex.to/jordan?amount=12.5&asset=XLM');
    expect('route' in result).toBe(true);
  });
});
