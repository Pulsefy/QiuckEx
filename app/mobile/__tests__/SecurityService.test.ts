import {
  clearSensitiveToken,
  getSecuritySettings,
  getSensitiveToken,
  hasFallbackPin,
  saveSecuritySettings,
  saveSensitiveToken,
  setFallbackPin,
  verifyFallbackPin,
} from "../services/security";

describe("security service", () => {
  it("persists and loads biometric settings", async () => {
    await saveSecuritySettings({ biometricLockEnabled: true });

    const loaded = await getSecuritySettings();
    expect(loaded.biometricLockEnabled).toBe(true);
  });

  it("stores fallback PIN securely and verifies it", async () => {
    await setFallbackPin("1234");

    expect(await hasFallbackPin()).toBe(true);
    expect(await verifyFallbackPin("1234")).toBe(true);
    expect(await verifyFallbackPin("0000")).toBe(false);
  });

  it("stores sensitive token and can clear it", async () => {
    await saveSensitiveToken("qex_session_abc123xyz");
    expect(await getSensitiveToken()).toBe("qex_session_abc123xyz");

    await clearSensitiveToken();
    expect(await getSensitiveToken()).toBeNull();
  });
});
