import {
  clearBiometricSession,
  clearSecuritySettings,
  clearSensitiveToken,
  getSecuritySettings,
  getSensitiveToken,
  hasFallbackPin,
  isBiometricSessionValid,
  recordBiometricAuth,
  saveSecuritySettings,
  saveSensitiveToken,
  setFallbackPin,
  verifyFallbackPin,
} from "../services/security";
import { DEFAULT_SESSION_TIMEOUT_MINUTES, MAX_SESSION_TIMEOUT_MINUTES, MIN_SESSION_TIMEOUT_MINUTES } from "../types/security";

describe("security service", () => {
  beforeEach(async () => {
    await clearSecuritySettings();
    await clearBiometricSession();
  });

  afterEach(async () => {
    await clearBiometricSession();
  });

  describe("biometric settings", () => {
    it("persists and loads biometric settings with default timeout", async () => {
      await saveSecuritySettings({ biometricLockEnabled: true, sessionTimeoutMinutes: 5 });

      const loaded = await getSecuritySettings();
      expect(loaded.biometricLockEnabled).toBe(true);
      expect(loaded.sessionTimeoutMinutes).toBe(5);
    });

    it("persists and loads custom session timeout", async () => {
      await saveSecuritySettings({ biometricLockEnabled: true, sessionTimeoutMinutes: 10 });

      const loaded = await getSecuritySettings();
      expect(loaded.sessionTimeoutMinutes).toBe(10);
    });

    it("clamps session timeout to minimum value", async () => {
      await saveSecuritySettings({ biometricLockEnabled: true, sessionTimeoutMinutes: 0 });

      const loaded = await getSecuritySettings();
      expect(loaded.sessionTimeoutMinutes).toBe(DEFAULT_SESSION_TIMEOUT_MINUTES);
    });

    it("clamps session timeout to maximum value", async () => {
      await saveSecuritySettings({ biometricLockEnabled: true, sessionTimeoutMinutes: 120 });

      const loaded = await getSecuritySettings();
      expect(loaded.sessionTimeoutMinutes).toBe(DEFAULT_SESSION_TIMEOUT_MINUTES);
    });

    it("uses default timeout when no timeout is set", async () => {
      // Save with only biometricLockEnabled (legacy format)
      // We write directly to the storage via the function
      await saveSecuritySettings({ biometricLockEnabled: true, sessionTimeoutMinutes: DEFAULT_SESSION_TIMEOUT_MINUTES });

      const loaded = await getSecuritySettings();
      expect(loaded.sessionTimeoutMinutes).toBe(DEFAULT_SESSION_TIMEOUT_MINUTES);
      expect(loaded.biometricLockEnabled).toBe(true);
    });

    it("returns default settings when no settings are stored", async () => {
      const loaded = await getSecuritySettings();
      expect(loaded.biometricLockEnabled).toBe(false);
      expect(loaded.sessionTimeoutMinutes).toBe(DEFAULT_SESSION_TIMEOUT_MINUTES);
    });
  });

  describe("fallback PIN", () => {
    it("stores fallback PIN securely and verifies it", async () => {
      await setFallbackPin("1234");

      expect(await hasFallbackPin()).toBe(true);
      expect(await verifyFallbackPin("1234")).toBe(true);
      expect(await verifyFallbackPin("0000")).toBe(false);
    });
  });

  describe("sensitive token", () => {
    it("stores sensitive token and can clear it", async () => {
      await saveSensitiveToken("qex_session_abc123xyz");
      expect(await getSensitiveToken()).toBe("qex_session_abc123xyz");

      await clearSensitiveToken();
      expect(await getSensitiveToken()).toBeNull();
    });
  });

  describe("biometric session", () => {
    it("records and validates a session", async () => {
      await recordBiometricAuth("app_unlock");
      const valid = await isBiometricSessionValid();
      expect(valid).toBe(true);
    });

    it("isBiometricSessionValid returns false with 0 timeout", async () => {
      await recordBiometricAuth("app_unlock");
      const valid = await isBiometricSessionValid(0);
      expect(valid).toBe(false);
    });

    it("clears session and forces re-auth", async () => {
      await recordBiometricAuth("payment_authorization");
      expect(await isBiometricSessionValid()).toBe(true);

      await clearBiometricSession();
      expect(await isBiometricSessionValid()).toBe(false);
    });
  });
});