// Lazily load native modules to avoid runtime errors in environments where
// native Expo modules (expo-crypto, expo-secure-store) are not available
// (web, node, or mismatched Expo Go). We provide JS fallbacks where possible.
let ExpoCrypto: any | undefined;
let ExpoSecureStore: any | undefined;
let AsyncStorage: any | undefined;

try {
  // Use require so bundlers won't eagerly fail when native modules are missing
  // (this can happen in web or test environments).
  // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
  ExpoCrypto = require("expo-crypto");
} catch (e) {
  ExpoCrypto = undefined;
}

try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
  ExpoSecureStore = require("expo-secure-store");
} catch (e) {
  ExpoSecureStore = undefined;
}

try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
  AsyncStorage = require("@react-native-async-storage/async-storage");
} catch (e) {
  AsyncStorage = undefined;
}

import type { SecuritySettings } from "@/types/security";

const SECURITY_SETTINGS_KEY = "quickex.security.settings";
const FALLBACK_PIN_HASH_KEY = "quickex.security.pinHash";
const SENSITIVE_TOKEN_KEY = "quickex.security.sensitiveToken";
const PIN_HASH_SALT = "quickex.v2.pin.salt";

const DEFAULT_SETTINGS: SecuritySettings = {
  biometricLockEnabled: false,
};

async function isSecureStoreAvailable() {
  try {
    if (
      ExpoSecureStore &&
      typeof ExpoSecureStore.isAvailableAsync === "function"
    ) {
      return await ExpoSecureStore.isAvailableAsync();
    }
    return false;
  } catch {
    return false;
  }
}

async function getItem(key: string) {
  if (await isSecureStoreAvailable()) {
    return ExpoSecureStore.getItemAsync(key);
  }

  // Fallback to AsyncStorage if available (less secure, used for web/testing)
  if (AsyncStorage && typeof AsyncStorage.getItem === "function") {
    try {
      return await AsyncStorage.getItem(key);
    } catch {
      return null;
    }
  }

  return null;
}

async function setItem(key: string, value: string) {
  if (await isSecureStoreAvailable()) {
    await ExpoSecureStore.setItemAsync(key, value, {
      keychainAccessible: ExpoSecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
    return;
  }

  if (AsyncStorage && typeof AsyncStorage.setItem === "function") {
    try {
      await AsyncStorage.setItem(key, value);
    } catch {
      // ignore
    }
  }
}

async function deleteItem(key: string) {
  if (await isSecureStoreAvailable()) {
    await ExpoSecureStore.deleteItemAsync(key);
    return;
  }

  if (AsyncStorage && typeof AsyncStorage.removeItem === "function") {
    try {
      await AsyncStorage.removeItem(key);
    } catch {
      // ignore
    }
  }
}

export async function getSecuritySettings(): Promise<SecuritySettings> {
  const raw = await getItem(SECURITY_SETTINGS_KEY);
  if (!raw) return DEFAULT_SETTINGS;

  try {
    const parsed = JSON.parse(raw) as Partial<SecuritySettings>;
    return {
      biometricLockEnabled: Boolean(parsed.biometricLockEnabled),
    };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export async function saveSecuritySettings(settings: SecuritySettings) {
  await setItem(SECURITY_SETTINGS_KEY, JSON.stringify(settings));
}

async function hashPin(pin: string) {
  // Prefer ExpoCrypto if available, otherwise use Web Crypto or Node crypto as fallback
  try {
    if (ExpoCrypto && typeof ExpoCrypto.digestStringAsync === "function") {
      return ExpoCrypto.digestStringAsync(
        ExpoCrypto.CryptoDigestAlgorithm.SHA256,
        `${PIN_HASH_SALT}:${pin}`,
      );
    }
  } catch (e) {
    // fallthrough to other methods
  }

  // Web Crypto API
  try {
    if (typeof globalThis?.crypto?.subtle?.digest === "function") {
      const data = new TextEncoder().encode(`${PIN_HASH_SALT}:${pin}`);
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
      .update(`${PIN_HASH_SALT}:${pin}`)
      .digest("hex");
  } catch (e) {
    // As a last resort, return a non-cryptographic string (shouldn't happen)
    return `${PIN_HASH_SALT}:${pin}`;
  }
}

export async function setFallbackPin(pin: string) {
  const pinHash = await hashPin(pin);
  await setItem(FALLBACK_PIN_HASH_KEY, pinHash);
}

export async function hasFallbackPin() {
  const pinHash = await getItem(FALLBACK_PIN_HASH_KEY);
  return Boolean(pinHash);
}

export async function verifyFallbackPin(pin: string) {
  const storedHash = await getItem(FALLBACK_PIN_HASH_KEY);
  if (!storedHash) return false;

  const incomingHash = await hashPin(pin);
  return storedHash === incomingHash;
}

export async function saveSensitiveToken(token: string) {
  await setItem(SENSITIVE_TOKEN_KEY, token);
}

export async function getSensitiveToken() {
  return getItem(SENSITIVE_TOKEN_KEY);
}

export async function clearSensitiveToken() {
  await deleteItem(SENSITIVE_TOKEN_KEY);
}
