/**
 * Integration tests for the wallet session service.
 *
 * Covers: save → get → validate → clear, expiry logic, last-wallet-type persistence.
 */
import {
  getWalletSession,
  saveWalletSession,
  clearWalletSession,
  isSessionRestorable,
  getLastWalletType,
  touchSession,
} from "../services/wallet-session";
import type { WalletSession } from "../services/wallet-session";

// AsyncStorage is already mocked in __mocks__/@react-native-async-storage/async-storage.js

const VALID_SESSION: WalletSession = {
  publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
  network: "testnet",
  walletType: "demo",
  connectedAt: Date.now(),
  lastConfirmedAt: new Date().toISOString(),
};

describe("wallet-session service", () => {
  afterEach(async () => {
    await clearWalletSession();
  });

  it("saves and retrieves a session", async () => {
    await saveWalletSession(VALID_SESSION);
    const session = await getWalletSession();

    expect(session).not.toBeNull();
    expect(session!.publicKey).toBe(VALID_SESSION.publicKey);
    expect(session!.network).toBe("testnet");
    expect(session!.walletType).toBe("demo");
    expect(session!.connectedAt).toBe(VALID_SESSION.connectedAt);
  });

  it("returns null when no session exists", async () => {
    const session = await getWalletSession();
    expect(session).toBeNull();
  });

  it("clears a session", async () => {
    await saveWalletSession(VALID_SESSION);
    await clearWalletSession();
    const session = await getWalletSession();
    expect(session).toBeNull();
  });

  it("persists last wallet type when saving a session", async () => {
    await saveWalletSession({ ...VALID_SESSION, walletType: "freighter" });
    const lastType = await getLastWalletType();
    expect(lastType).toBe("freighter");
  });

  it("returns null for last wallet type when nothing was saved", async () => {
    const lastType = await getLastWalletType();
    expect(lastType).toBeNull();
  });

  describe("isSessionRestorable", () => {
    it("returns true for a fresh session", () => {
      expect(isSessionRestorable(VALID_SESSION)).toBe(true);
    });

    it("returns false for a session older than 7 days", () => {
      const eightDaysAgo = Date.now() - 8 * 24 * 60 * 60 * 1000;
      const oldSession: WalletSession = {
        ...VALID_SESSION,
        connectedAt: eightDaysAgo,
        lastConfirmedAt: new Date(eightDaysAgo).toISOString(),
      };
      expect(isSessionRestorable(oldSession)).toBe(false);
    });

    it("returns false when lastConfirmedAt is stale", () => {
      const recentConnectedAt = Date.now() - 1000;
      const staleConfirmedAt = new Date(
        Date.now() - 8 * 24 * 60 * 60 * 1000,
      ).toISOString();
      const session: WalletSession = {
        ...VALID_SESSION,
        connectedAt: recentConnectedAt,
        lastConfirmedAt: staleConfirmedAt,
      };
      expect(isSessionRestorable(session)).toBe(false);
    });
  });

  describe("touchSession", () => {
    it("updates the lastConfirmedAt timestamp", async () => {
      const originalDate = new Date(Date.now() - 60000).toISOString();
      await saveWalletSession({
        ...VALID_SESSION,
        lastConfirmedAt: originalDate,
      });

      await touchSession();

      const session = await getWalletSession();
      expect(session).not.toBeNull();
      expect(session!.lastConfirmedAt).not.toBe(originalDate);
    });
  });
});
