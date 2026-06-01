import {
  clearLocalData,
} from "../services/local-data";
import {
  getWalletSession,
  saveWalletSession,
  getLastWalletType,
  clearWalletSession,
} from "../services/wallet-session";
import {
  getSecuritySettings,
  hasFallbackPin,
  getSensitiveToken,
  saveSecuritySettings,
  setFallbackPin,
  saveSensitiveToken,
} from "../services/security";
import type { WalletSession } from "../services/wallet-session";

const VALID_SESSION: WalletSession = {
  publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
  network: "testnet",
  walletType: "demo",
  connectedAt: Date.now(),
  lastConfirmedAt: new Date().toISOString(),
};

describe("local data service", () => {
  afterEach(async () => {
    await clearWalletSession();
  });

  it("clears wallet session, secure storage, and cached app state", async () => {
    await saveWalletSession(VALID_SESSION);
    await saveSecuritySettings({ biometricLockEnabled: true });
    await setFallbackPin("1234");
    await saveSensitiveToken("qex_session_test_token");

    await clearLocalData();

    expect(await getWalletSession()).toBeNull();
    expect(await getLastWalletType()).toBeNull();
    expect(await getSecuritySettings()).toEqual({ biometricLockEnabled: false });
    expect(await hasFallbackPin()).toBe(false);
    expect(await getSensitiveToken()).toBeNull();
  });
});
