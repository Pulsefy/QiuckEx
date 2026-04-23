import AsyncStorage from "@react-native-async-storage/async-storage";

export type WalletNetwork = "testnet" | "mainnet";

export interface WalletSession {
  publicKey: string;
  network: WalletNetwork;
  connectedAt: number;
}

const WALLET_SESSION_KEY = "quickex.wallet.session.v1";

export async function getWalletSession(): Promise<WalletSession | null> {
  try {
    const raw = await AsyncStorage.getItem(WALLET_SESSION_KEY);
    if (!raw) return null;

    const parsed = JSON.parse(raw) as Partial<WalletSession>;
    if (!parsed.publicKey || !parsed.network || !parsed.connectedAt) {
      return null;
    }

    return {
      publicKey: parsed.publicKey,
      network: parsed.network,
      connectedAt: parsed.connectedAt,
    };
  } catch {
    return null;
  }
}

export async function saveWalletSession(session: WalletSession): Promise<void> {
  await AsyncStorage.setItem(WALLET_SESSION_KEY, JSON.stringify(session));
}

export async function clearWalletSession(): Promise<void> {
  await AsyncStorage.removeItem(WALLET_SESSION_KEY);
}
