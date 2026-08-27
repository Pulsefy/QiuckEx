import AsyncStorage from "@react-native-async-storage/async-storage";
import * as SecureStore from "expo-secure-store";

const INSTALL_MARKER_KEY = "quickex.secure-storage.install-marker";
const SENSITIVE_KEYS = [
  "quickex.security.pinHash",
  "quickex.security.sensitiveToken",
  "quickex.security.biometricSession",
  "quickex.wallet.session.v3",
] as const;

let initialization: Promise<void> | undefined;

async function initializeSecureStorage(): Promise<void> {
  if (!initialization) {
    initialization = (async () => {
      const marker = await AsyncStorage.getItem(INSTALL_MARKER_KEY);
      if (!marker && (await SecureStore.isAvailableAsync())) {
        await Promise.all(
          SENSITIVE_KEYS.map((key) => SecureStore.deleteItemAsync(key)),
        );
      }
      await AsyncStorage.setItem(INSTALL_MARKER_KEY, "1");
    })();
  }
  await initialization;
}

export async function getSecureItem(key: string): Promise<string | null> {
  await initializeSecureStorage();
  if (!(await SecureStore.isAvailableAsync())) return null;
  return SecureStore.getItemAsync(key);
}

export async function setSecureItem(key: string, value: string): Promise<void> {
  await initializeSecureStorage();
  if (!(await SecureStore.isAvailableAsync())) {
    throw new Error("Secure storage is unavailable on this device");
  }
  await SecureStore.setItemAsync(key, value, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

export async function deleteSecureItem(key: string): Promise<void> {
  await initializeSecureStorage();
  if (!(await SecureStore.isAvailableAsync())) return;
  await SecureStore.deleteItemAsync(key);
}
