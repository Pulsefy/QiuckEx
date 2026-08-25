import React from "react";
import { renderHook, act } from "@testing-library/react-native";
import * as LocalAuthentication from "expo-local-authentication";
import { SecurityProvider, useSecurity } from "../hooks/use-security";
import * as SecurityService from "../services/security";

jest.mock("expo-local-authentication", () => ({
  hasHardwareAsync: jest.fn(),
  isEnrolledAsync: jest.fn(),
  authenticateAsync: jest.fn(),
}));

jest.mock("../services/security", () => ({
  ...jest.requireActual("../services/security"),
  getSecuritySettings: jest.fn(),
  hasFallbackPin: jest.fn(),
  isBiometricSessionValid: jest.fn(),
  recordBiometricAuth: jest.fn(),
  clearBiometricSession: jest.fn(),
  saveSecuritySettings: jest.fn(),
}));

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <SecurityProvider>{children}</SecurityProvider>
);

describe("useSecurity Biometric Fallback (MOB-64)", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (SecurityService.getSecuritySettings as jest.Mock).mockResolvedValue({
      biometricLockEnabled: true,
      sessionTimeoutMinutes: 5,
    });
    (SecurityService.hasFallbackPin as jest.Mock).mockResolvedValue(true);
    (SecurityService.isBiometricSessionValid as jest.Mock).mockResolvedValue(false);
  });

  const setupHook = async () => {
    const { result, waitForNextUpdate } = renderHook(() => useSecurity(), { wrapper });
    // Wait for isReady to become true
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 0));
    });
    return result;
  };

  it("handles no-hardware state correctly", async () => {
    (LocalAuthentication.hasHardwareAsync as jest.Mock).mockResolvedValue(false);
    (LocalAuthentication.isEnrolledAsync as jest.Mock).mockResolvedValue(false);

    const result = await setupHook();
    expect(result.current.isBiometricAvailable).toBe(false);

    // Call authenticateForSensitiveAction without awaiting it (so we don't block on PIN prompt)
    let authPromise: Promise<boolean>;
    act(() => {
      authPromise = result.current.authenticateForSensitiveAction("app_unlock");
    });

    // Verify authenticateAsync was NOT called because hardware is missing
    expect(LocalAuthentication.authenticateAsync).not.toHaveBeenCalled();
  });

  it("handles not-enrolled state correctly", async () => {
    (LocalAuthentication.hasHardwareAsync as jest.Mock).mockResolvedValue(true);
    (LocalAuthentication.isEnrolledAsync as jest.Mock).mockResolvedValue(false);

    const result = await setupHook();
    expect(result.current.isBiometricAvailable).toBe(false);

    let authPromise: Promise<boolean>;
    act(() => {
      authPromise = result.current.authenticateForSensitiveAction("app_unlock");
    });

    expect(LocalAuthentication.authenticateAsync).not.toHaveBeenCalled();
  });

  it("handles lockout state correctly", async () => {
    (LocalAuthentication.hasHardwareAsync as jest.Mock).mockResolvedValue(true);
    (LocalAuthentication.isEnrolledAsync as jest.Mock).mockResolvedValue(true);
    (LocalAuthentication.authenticateAsync as jest.Mock).mockResolvedValue({
      success: false,
      error: "lockout",
    });

    const result = await setupHook();
    expect(result.current.isBiometricAvailable).toBe(true);

    let authPromise: Promise<boolean>;
    await act(async () => {
      authPromise = result.current.authenticateForSensitiveAction("app_unlock");
      // Yield to allow authenticateAsync to complete
      await new Promise(resolve => setTimeout(resolve, 0));
    });

    expect(LocalAuthentication.authenticateAsync).toHaveBeenCalled();
  });
  
  it("disables biometric lock if PIN is missing and biometrics fail (legacy edge case)", async () => {
    (SecurityService.hasFallbackPin as jest.Mock).mockResolvedValue(false);
    (LocalAuthentication.hasHardwareAsync as jest.Mock).mockResolvedValue(false);
    (LocalAuthentication.isEnrolledAsync as jest.Mock).mockResolvedValue(false);

    const result = await setupHook();
    
    let authenticated = true;
    await act(async () => {
      authenticated = await result.current.authenticateForSensitiveAction("app_unlock");
    });

    // Should return false because we couldn't authenticate, BUT it should also disable the lock
    expect(authenticated).toBe(false);
    expect(SecurityService.saveSecuritySettings).toHaveBeenCalledWith(
      expect.objectContaining({ biometricLockEnabled: false })
    );
    expect(SecurityService.clearBiometricSession).toHaveBeenCalled();
    expect(result.current.isAppLocked).toBe(false);
  });
});
