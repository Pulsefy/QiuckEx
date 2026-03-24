import * as Crypto from "expo-crypto";
import * as SecureStore from "expo-secure-store";

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
    return await SecureStore.isAvailableAsync();
  } catch {
    return false;
  }
}

async function getItem(key: string) {
  if (!(await isSecureStoreAvailable())) {
    return null;
  }

  return SecureStore.getItemAsync(key);
}

async function setItem(key: string, value: string) {
  if (!(await isSecureStoreAvailable())) {
    return;
  }

  await SecureStore.setItemAsync(key, value, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

async function deleteItem(key: string) {
  if (!(await isSecureStoreAvailable())) {
    return;
  }

  await SecureStore.deleteItemAsync(key);
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
  return Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    `${PIN_HASH_SALT}:${pin}`,
  );
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
