/**
 * Integration tests for the wallet session service.
 *
 * Covers: save → get → validate → clear, expiry logic, last-wallet-type persistence,
 * environment mismatch detection, stale session recovery.
 */
import {
  getWalletSession,
  saveWalletSession,
  clearWalletSession,
  isSessionRestorable,
  getLastWalletType,
  touchSession,
  getSessionInvalidReason,
  isSessionEnvironmentMismatch,
  resetInvalidSession,
} from "../services/wallet-session";
// eslint-disable-next-line @typescript-eslint/no-unused-vars
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

  it("saves environmentId when provided", async () => {
    await saveWalletSession(VALID_SESSION, "staging", "staging-v1");
    const session = await getWalletSession();

    expect(session).not.toBeNull();
    expect(session!.environmentId).toBe("staging");
    expect(session!.buildTag).toBe("staging-v1");
  });

  it("saves without environmentId when not provided", async () => {
    await saveWalletSession(VALID_SESSION);
    const session = await getWalletSession();

    expect(session).not.toBeNull();
    expect(session!.environmentId).toBeUndefined();
    expect(session!.buildTag).toBeUndefined();
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

  describe("getSessionInvalidReason", () => {
    it("returns none for a valid session", () => {
      const result = getSessionInvalidReason(VALID_SESSION);
      expect(result.invalid).toBe(false);
    });

    it("returns corrupted for null session", () => {
      const result = getSessionInvalidReason(null);
      expect(result.invalid).toBe(true);
      expect(result.reason).toBe("corrupted");
    });

    it("returns expired for session older than 7 days", () => {
      const eightDaysAgo = Date.now() - 8 * 24 * 60 * 60 * 1000;
      const oldSession: WalletSession = {
        ...VALID_SESSION,
        connectedAt: eightDaysAgo,
        lastConfirmedAt: new Date(eightDaysAgo).toISOString(),
      };
      const result = getSessionInvalidReason(oldSession);
      expect(result.invalid).toBe(true);
      expect(result.reason).toBe("expired");
    });

    it("returns environment_mismatch when environmentId differs", () => {
      const session: WalletSession = {
        ...VALID_SESSION,
        environmentId: "staging",
      };
      const result = getSessionInvalidReason(session, "production");
      expect(result.invalid).toBe(true);
      expect(result.reason).toBe("environment_mismatch");
    });

    it("returns none when environmentId matches", () => {
      const session: WalletSession = {
        ...VALID_SESSION,
        environmentId: "production",
      };
      const result = getSessionInvalidReason(session, "production");
      expect(result.invalid).toBe(false);
    });

    it("returns none when session has no environmentId (backward compat)", () => {
      const result = getSessionInvalidReason(VALID_SESSION, "production");
      expect(result.invalid).toBe(false);
    });
  });

  describe("isSessionEnvironmentMismatch", () => {
    it("returns true when environmentId differs from current", () => {
      const session: WalletSession = {
        ...VALID_SESSION,
        environmentId: "staging",
      };
      expect(isSessionEnvironmentMismatch(session, "production")).toBe(true);
    });

    it("returns false when environmentId matches", () => {
      const session: WalletSession = {
        ...VALID_SESSION,
        environmentId: "testnet",
      };
      expect(isSessionEnvironmentMismatch(session, "testnet")).toBe(false);
    });

    it("returns false when session has no environmentId", () => {
      expect(isSessionEnvironmentMismatch(VALID_SESSION, "production")).toBe(false);
    });
  });

  describe("resetInvalidSession", () => {
    it("returns none when session is valid", async () => {
      await saveWalletSession(VALID_SESSION);
      const result = await resetInvalidSession("production");
      expect(result.reason).toBe("none");
      expect(result.session).not.toBeUndefined();
    });

    it("returns expired and clears session for expired session", async () => {
      const eightDaysAgo = Date.now() - 8 * 24 * 60 * 60 * 1000;
      await saveWalletSession({
        ...VALID_SESSION,
        connectedAt: eightDaysAgo,
        lastConfirmedAt: new Date(eightDaysAgo).toISOString(),
      });
      const result = await resetInvalidSession("production");
      expect(result.reason).toBe("expired");
      const session = await getWalletSession();
      expect(session).toBeNull();
    });

    it("returns environment_mismatch and clears session when env differs", async () => {
      await saveWalletSession(
        { ...VALID_SESSION, environmentId: "staging" },
        "staging",
      );
      const result = await resetInvalidSession("production");
      expect(result.reason).toBe("environment_mismatch");
      expect(result.session).not.toBeUndefined();
      expect(result.session!.environmentId).toBe("staging");
      const session = await getWalletSession();
      expect(session).toBeNull();
    });

    it("returns corrupted when no session exists", async () => {
      const result = await resetInvalidSession("production");
      expect(result.reason).toBe("corrupted");
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
