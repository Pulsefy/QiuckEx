import AsyncStorage from "@react-native-async-storage/async-storage";

import {
  deleteSecureItem,
  getSecureItem,
  setSecureItem,
} from "./secure-storage";

// Lazily load native modules to avoid runtime errors in environments where
// native Expo modules (expo-crypto, expo-secure-store) are not available
// (web, node, or mismatched Expo Go). We provide JS fallbacks where possible.
let ExpoCrypto: any | undefined;

try {
  // Use require so bundlers won't eagerly fail when native modules are missing
  // (this can happen in web or test environments).
  // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
  ExpoCrypto = require("expo-crypto");
} catch (e) {
  ExpoCrypto = undefined;
}

import type {
  BiometricSessionInfo,
  SecurityAuthReason,
  SecuritySettings,
} from "@/types/security";
import {
  DEFAULT_SESSION_TIMEOUT_MINUTES,
  MIN_SESSION_TIMEOUT_MINUTES,
  MAX_SESSION_TIMEOUT_MINUTES,
} from "@/types/security";

const SECURITY_SETTINGS_KEY = "quickex.security.settings";
const FALLBACK_PIN_HASH_KEY = "quickex.security.pinHash";
const SENSITIVE_TOKEN_KEY = "quickex.security.sensitiveToken";
const PIN_HASH_LENGTH = 16;

const BIOMETRIC_SESSION_KEY = "quickex.security.biometricSession";

export const DEFAULT_SETTINGS: SecuritySettings = {
  biometricLockEnabled: false,
  sessionTimeoutMinutes: DEFAULT_SESSION_TIMEOUT_MINUTES,
};

export async function getSecuritySettings(): Promise<SecuritySettings> {
  const raw = await AsyncStorage.getItem(SECURITY_SETTINGS_KEY);
  if (!raw) return DEFAULT_SETTINGS;

  try {
    const parsed = JSON.parse(raw) as Partial<SecuritySettings>;
    return {
      biometricLockEnabled: Boolean(parsed.biometricLockEnabled),
      sessionTimeoutMinutes:
        typeof parsed.sessionTimeoutMinutes === "number" &&
        parsed.sessionTimeoutMinutes >= MIN_SESSION_TIMEOUT_MINUTES &&
        parsed.sessionTimeoutMinutes <= MAX_SESSION_TIMEOUT_MINUTES
          ? parsed.sessionTimeoutMinutes
          : DEFAULT_SESSION_TIMEOUT_MINUTES,
    };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export async function saveSecuritySettings(settings: SecuritySettings) {
  await AsyncStorage.setItem(SECURITY_SETTINGS_KEY, JSON.stringify(settings));
}

/**
 * Removes all stored security settings, returning to the default state.
 */
export async function clearSecuritySettings() {
  await AsyncStorage.removeItem(SECURITY_SETTINGS_KEY);
}

// ── Biometric Session Management ──────────────────────────────────────────────

/**
 * Records a successful biometric/PIN authentication event.
 * This is used to allow subsequent low-risk actions without re-prompting.
 */
export async function recordBiometricAuth(reason: SecurityAuthReason) {
  const sessionInfo: BiometricSessionInfo = {
    lastAuthenticatedAt: new Date().toISOString(),
    lastAuthReason: reason,
  };
  await setSecureItem(BIOMETRIC_SESSION_KEY, JSON.stringify(sessionInfo));
}

/**
 * Retrieves the last biometric session info.
 */
export async function getBiometricSession(): Promise<BiometricSessionInfo | null> {
  const raw = await getSecureItem(BIOMETRIC_SESSION_KEY);
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw) as BiometricSessionInfo;
    if (!parsed.lastAuthenticatedAt || !parsed.lastAuthReason) return null;
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Clears the biometric session, forcing re-authentication on the next action.
 */
export async function clearBiometricSession() {
  await deleteSecureItem(BIOMETRIC_SESSION_KEY);
}

/**
 * Checks whether the current biometric session is still valid based on
 * the configured timeout.
 *
 * @param sessionTimeoutMinutes - The configured timeout in minutes.
 * @returns `true` if the session is still valid (not expired).
 */
export async function isBiometricSessionValid(
  sessionTimeoutMinutes?: number,
): Promise<boolean> {
  const session = await getBiometricSession();
  if (!session) return false;

  const timeoutMs =
    (sessionTimeoutMinutes ?? DEFAULT_SESSION_TIMEOUT_MINUTES) * 60 * 1000;
  const lastAuth = new Date(session.lastAuthenticatedAt).getTime();
  const now = Date.now();

  return now - lastAuth < timeoutMs;
}

/**
 * Returns a human-readable message explaining when the session will expire
 * or has expired.
 */
export async function getSessionExpiryExplanation(): Promise<string> {
  const settings = await getSecuritySettings();
  const session = await getBiometricSession();

  if (!session) {
    return "No active biometric session. Authentication is required.";
  }

  const timeoutMs = settings.sessionTimeoutMinutes * 60 * 1000;
  const lastAuth = new Date(session.lastAuthenticatedAt).getTime();
  const now = Date.now();
  const elapsedMs = now - lastAuth;

  if (elapsedMs >= timeoutMs) {
    const expiredSinceMs = elapsedMs - timeoutMs;
    const expiredMinutes = Math.floor(expiredSinceMs / 60000);
    const expiredSeconds = Math.floor((expiredSinceMs % 60000) / 1000);
    if (expiredMinutes > 0) {
      return `Your session expired ${expiredMinutes} minute${expiredMinutes > 1 ? "s" : ""} ago. Please re-authenticate to continue.`;
    }
    return `Your session expired ${expiredSeconds} second${expiredSeconds !== 1 ? "s" : ""} ago. Please re-authenticate to continue.`;
  }

  const remainingMs = timeoutMs - elapsedMs;
  const remainingMinutes = Math.floor(remainingMs / 60000);
  const remainingSeconds = Math.floor((remainingMs % 60000) / 1000);

  if (remainingMinutes > 0) {
    return `Your session expires in ${remainingMinutes} minute${remainingMinutes > 1 ? "s" : ""}.`;
  }
  return `Your session expires in ${remainingSeconds} second${remainingSeconds !== 1 ? "s" : ""}.`;
}

async function createPinSalt(): Promise<string> {
  try {
    if (ExpoCrypto && typeof ExpoCrypto.getRandomBytesAsync === "function") {
      const bytes = await ExpoCrypto.getRandomBytesAsync(PIN_HASH_LENGTH);
      return Array.from(bytes, (byte: number) => byte.toString(16).padStart(2, "0")).join("");
    }
  } catch {
    // Try the platform-independent crypto implementations below.
  }

  try {
    if (typeof globalThis?.crypto?.getRandomValues === "function") {
      const bytes = globalThis.crypto.getRandomValues(new Uint8Array(PIN_HASH_LENGTH));
      return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    }
  } catch {
    // Try Node crypto in test and development environments.
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
    const nodeCrypto = require("crypto");
    return nodeCrypto.randomBytes(PIN_HASH_LENGTH).toString("hex");
  } catch {
    throw new Error("A cryptographically secure random source is unavailable");
  }
}

async function hashPin(pin: string, salt: string) {
  // Prefer ExpoCrypto if available, otherwise use Web Crypto or Node crypto as fallback
  try {
    if (ExpoCrypto && typeof ExpoCrypto.digestStringAsync === "function") {
      return ExpoCrypto.digestStringAsync(
        ExpoCrypto.CryptoDigestAlgorithm.SHA256,
        `${salt}:${pin}`,
      );
    }
  } catch (e) {
    // fallthrough to other methods
  }

  // Web Crypto API
  try {
    if (typeof globalThis?.crypto?.subtle?.digest === "function") {
      const data = new TextEncoder().encode(`${salt}:${pin}`);
      const hash = await globalThis.crypto.subtle.digest("SHA-256", data);
      // convert to hex
      const arr = Array.from(new Uint8Array(hash));
      return arr.map((b) => b.toString(16).padStart(2, "0")).join("");
    }
  } catch (e) {
    // continue to Node fallback
  }

  // Node crypto fallback (if running in node)
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
    const nodeCrypto = require("crypto");
    return nodeCrypto
      .createHash("sha256")
      .update(`${salt}:${pin}`)
      .digest("hex");
  } catch (e) {
    // As a last resort, return a non-cryptographic string (shouldn't happen)
    throw new Error("No cryptographic hash implementation is available");
  }
}

export async function setFallbackPin(pin: string) {
  const salt = await createPinSalt();
  const hash = await hashPin(pin, salt);
  await setSecureItem(FALLBACK_PIN_HASH_KEY, JSON.stringify({ salt, hash }));
}

export async function hasFallbackPin() {
  const stored = await getSecureItem(FALLBACK_PIN_HASH_KEY);
  if (!stored) return false;
  try {
    const parsed = JSON.parse(stored) as { salt?: string; hash?: string };
    return Boolean(parsed.salt && parsed.hash);
  } catch {
    return false;
  }
}

export async function verifyFallbackPin(pin: string) {
  const stored = await getSecureItem(FALLBACK_PIN_HASH_KEY);
  if (!stored) return false;

  try {
    const parsed = JSON.parse(stored) as { salt?: string; hash?: string };
    if (!parsed.salt || !parsed.hash) return false;
    return parsed.hash === (await hashPin(pin, parsed.salt));
  } catch {
    return false;
  }
}

export async function saveSensitiveToken(token: string) {
  await setSecureItem(SENSITIVE_TOKEN_KEY, token);
}

export async function getSensitiveToken() {
  return getSecureItem(SENSITIVE_TOKEN_KEY);
}

export async function clearSensitiveToken() {
  await deleteSecureItem(SENSITIVE_TOKEN_KEY);
}

export async function clearSensitiveSecurityData(): Promise<void> {
  await Promise.all([
    deleteSecureItem(FALLBACK_PIN_HASH_KEY),
    deleteSecureItem(SENSITIVE_TOKEN_KEY),
    deleteSecureItem(BIOMETRIC_SESSION_KEY),
  ]);
}

export async function clearSecurityData(): Promise<void> {
  await Promise.all([
    clearSecuritySettings(),
    clearSensitiveSecurityData(),
  ]);
}