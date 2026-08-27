# Mobile Storage Inventory

Storage is classified by the most sensitive value a key can contain. Secrets and wallet session material use `expo-secure-store` with `WHEN_UNLOCKED_THIS_DEVICE_ONLY`. AsyncStorage is reserved for non-sensitive preferences, cached data, and recoverable app state.

| Key or pattern | Classification | Storage mechanism | Cleanup |
| --- | --- | --- | --- |
| `quickex.security.pinHash` | Secret: salted PIN hash | SecureStore | `clearSecurityData` and app data wipe |
| `quickex.security.sensitiveToken` | Secret: session token | SecureStore | `clearSecurityData` and app data wipe |
| `quickex.security.biometricSession` | Sensitive: short-lived auth session | SecureStore | `clearSecurityData` and app data wipe |
| `quickex.wallet.session.v3` | Sensitive: wallet session state | SecureStore | `clearWalletSession` and app data wipe |
| `quickex.secure-storage.install-marker` | Non-sensitive lifecycle marker | AsyncStorage | App data wipe; absence triggers SecureStore purge on next install |
| `quickex.wallet.lastType` | Non-sensitive wallet preference | AsyncStorage | App data wipe |
| `quickex.security.settings` | Non-sensitive security preferences | AsyncStorage | `clearSecuritySettings` and app data wipe |
| `@quickex/environment` | Non-sensitive environment preference | AsyncStorage | `resetEnvironment` and app data wipe |
| `quickex_onboarding_completed` | Non-sensitive onboarding preference | AsyncStorage | Onboarding reset |
| `quickex_onboarding_events` | Non-sensitive diagnostics | AsyncStorage | Onboarding reset |
| `quickex_session_id` | Pseudonymous analytics identifier | AsyncStorage | Onboarding reset |
| `contacts` | User data, not authentication material | AsyncStorage | App data wipe |
| `app_notifications` | Non-sensitive notification state | AsyncStorage | App data wipe |
| `quickex.offline-queue.v1` | Recoverable transaction metadata | AsyncStorage | Queue clear and app data wipe |
| `@qex_tx_cache_*` | Recoverable transaction cache | AsyncStorage | Cache clear and app data wipe |
| `@qex_profile_cache_*` | Recoverable profile cache | AsyncStorage | Cache clear and app data wipe |
| `@contract_registry` | Recoverable contract metadata cache | AsyncStorage | App data wipe |
| `quickex.background-sync.settings.v1` | Non-sensitive sync preference | AsyncStorage | App data wipe |
| `quickex.background-sync.snapshot.v1` | Recoverable sync metadata | AsyncStorage | App data wipe |
| `@quickex_theme_mode` and profile theme keys | Non-sensitive display preference | AsyncStorage | Profile/theme reset |
| `qex_sound_enabled_v1` | Non-sensitive notification preference | AsyncStorage | App data wipe |

## PIN storage

A PIN is never persisted. `setFallbackPin` generates a cryptographically random per-PIN salt and stores only `{ salt, hash }` in SecureStore. Verification hashes the supplied PIN with the stored salt and compares the result. If no cryptographic random source or hash implementation is available, setting a PIN fails rather than storing recoverable material.

## Sign-out and uninstall

The wallet disconnect flow clears the wallet session and sensitive session token. The Settings "Clear Local Data" flow additionally clears all AsyncStorage state, security settings, PIN hash, biometric session, and SecureStore session material. Native uninstall removes the platform keychain/keystore according to the platform lifecycle; the app does not retain a recoverable secret outside SecureStore.
