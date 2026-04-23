import AsyncStorage from "@react-native-async-storage/async-storage";
import type { StellarNetwork, WalletType } from "../types/wallet";

export type WalletNetwork = StellarNetwork;

export interface WalletSession {
  publicKey: string;
  network: WalletNetwork;
  walletType: WalletType;
  connectedAt: number;
  /** ISO-8601 timestamp when the session was last confirmed active */
  lastConfirmedAt: string;
}

const WALLET_SESSION_KEY = "quickex.wallet.session.v2";
const LAST_WALLET_TYPE_KEY = "quickex.wallet.lastType";

/**
 * Maximum age for a session to be considered restorable (7 days).
 * After this the user must re-connect explicitly.
 */
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

// ── Helpers ──────────────────────────────────────────────────────────────────

function isValidWalletType(value: unknown): value is WalletType {
  return (
    typeof value === "string" &&
    ["freighter", "lobstr", "xbull", "albedo", "demo"].includes(value)
  );
}

function isValidNetwork(value: unknown): value is WalletNetwork {
  return value === "testnet" || value === "mainnet";
}

// ── Session CRUD ─────────────────────────────────────────────────────────────

export async function getWalletSession(): Promise<WalletSession | null> {
  try {
    const raw = await AsyncStorage.getItem(WALLET_SESSION_KEY);
    if (!raw) return null;

    const parsed = JSON.parse(raw) as Partial<WalletSession>;

    if (
      !parsed.publicKey ||
      !isValidNetwork(parsed.network) ||
      !isValidWalletType(parsed.walletType) ||
      !parsed.connectedAt
    ) {
      // Corrupted session – clear it so the user starts fresh
      await clearWalletSession();
      return null;
    }

    return {
      publicKey: parsed.publicKey,
      network: parsed.network,
      walletType: parsed.walletType,
      connectedAt: parsed.connectedAt,
      lastConfirmedAt: parsed.lastConfirmedAt ?? new Date(parsed.connectedAt).toISOString(),
    };
  } catch {
    return null;
  }
}

export async function saveWalletSession(session: WalletSession): Promise<void> {
  await AsyncStorage.setItem(WALLET_SESSION_KEY, JSON.stringify(session));
  // Also persist the wallet type so we can offer it as default next time
  await AsyncStorage.setItem(LAST_WALLET_TYPE_KEY, session.walletType);
}

export async function clearWalletSession(): Promise<void> {
  await AsyncStorage.removeItem(WALLET_SESSION_KEY);
}

// ── Session Validation ───────────────────────────────────────────────────────

/**
 * Returns `true` when the stored session is within the max-age window and
 * safe to restore automatically.
 */
export function isSessionRestorable(session: WalletSession): boolean {
  const now = Date.now();
  const age = now - session.connectedAt;

  if (age > SESSION_MAX_AGE_MS) return false;

  // Also check the last-confirmed timestamp – if it's stale the user might
  // have changed wallets externally.
  try {
    const lastConfirmed = new Date(session.lastConfirmedAt).getTime();
    if (Number.isNaN(lastConfirmed)) return false;
    if (now - lastConfirmed > SESSION_MAX_AGE_MS) return false;
  } catch {
    return false;
  }

  return true;
}

/**
 * Call after a successful wallet interaction to bump the last-confirmed
 * timestamp, keeping the session alive.
 */
export async function touchSession(): Promise<void> {
  const session = await getWalletSession();
  if (!session) return;

  session.lastConfirmedAt = new Date().toISOString();
  await saveWalletSession(session);
}

// ── Last Wallet Type ─────────────────────────────────────────────────────────

export async function getLastWalletType(): Promise<WalletType | null> {
  try {
    const raw = await AsyncStorage.getItem(LAST_WALLET_TYPE_KEY);
    if (!raw) return null;
    return isValidWalletType(raw) ? raw : null;
  } catch {
    return null;
  }
}
