/**
 * Shared public key resolution for frontend API calls.
 * Used by analytics and activity feed hooks to resolve the user's
 * Stellar public key from localStorage or environment variables.
 */

const DEFAULT_PUBLIC_KEY =
  "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const PUBLIC_KEY_REGEX = /^G[A-Z2-7]{55}$/;
const PUBLIC_KEY_STORAGE_CANDIDATES = [
  "quickex.publicKey",
  "quickex.walletPublicKey",
  "walletPublicKey",
  "publicKey",
];

/**
 * Resolve the user's Stellar public key from available sources:
 * 1. localStorage (browser wallets store the key under known keys)
 * 2. Environment variable (NEXT_PUBLIC_QUICKEX_ANALYTICS_PUBLIC_KEY)
 * 3. Fallback to a zero-value default key
 */
export function resolvePublicKey(): string {
  if (typeof window !== "undefined") {
    for (const key of PUBLIC_KEY_STORAGE_CANDIDATES) {
      const value = window.localStorage.getItem(key)?.trim();
      if (value && PUBLIC_KEY_REGEX.test(value)) {
        return value;
      }
    }
  }

  const fromEnv =
    process.env.NEXT_PUBLIC_QUICKEX_ANALYTICS_PUBLIC_KEY?.trim();
  if (fromEnv && PUBLIC_KEY_REGEX.test(fromEnv)) {
    return fromEnv;
  }

  return DEFAULT_PUBLIC_KEY;
}
