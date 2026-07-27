import AsyncStorage from "@react-native-async-storage/async-storage";

import { clearSecurityData } from "./security";
import { resetEnvironment } from "./environment-storage";
import { clearWalletSession } from "./wallet-session";

export async function clearLocalData(): Promise<void> {
  try {
    if (AsyncStorage && typeof AsyncStorage.clear === "function") {
      await AsyncStorage.clear();
    }
  } catch (error) {
    console.error("Failed to clear AsyncStorage during local data wipe", error);
  }

  try {
    await clearSecurityData();
  } catch (error) {
    console.error("Failed to clear secure storage during local data wipe", error);
  }

  try {
    await clearWalletSession();
  } catch (error) {
    console.error("Failed to clear wallet session during local data wipe", error);
  }

  try {
    await resetEnvironment();
  } catch (error) {
    console.error("Failed to reset environment during local data wipe", error);
  }
}
