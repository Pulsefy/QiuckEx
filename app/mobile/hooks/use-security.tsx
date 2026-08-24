import * as LocalAuthentication from "expo-local-authentication";
import React, {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useMemo,
    useRef,
    useState,
} from "react";
import { AppState, Platform } from "react-native";

import { PinAuthModal } from "@/components/security/pin-auth-modal";
import {
    clearBiometricSession,
    clearSensitiveToken,
    getSecuritySettings,
    getSensitiveToken,
    getSessionExpiryExplanation,
    hasFallbackPin,
    isBiometricSessionValid,
    recordBiometricAuth,
    saveSecuritySettings,
    saveSensitiveToken,
    setFallbackPin,
    verifyFallbackPin,
} from "@/services/security";
import type { SecurityAuthReason, SecuritySettings } from "@/types/security";

interface ToggleResult {
  ok: boolean;
  error?: string;
}

interface SavePinResult {
  ok: boolean;
  error?: string;
}

interface SecurityContextValue {
  isReady: boolean;
  isAppLocked: boolean;
  isBiometricAvailable: boolean;
  hasPinConfigured: boolean;
  settings: SecuritySettings;
  setBiometricLockEnabled: (enabled: boolean) => Promise<ToggleResult>;
  savePin: (pin: string) => Promise<SavePinResult>;
  unlockApp: () => Promise<boolean>;
  authenticateForSensitiveAction: (
    reason: SecurityAuthReason,
  ) => Promise<boolean>;
  saveSensitiveSessionToken: (token: string) => Promise<void>;
  getSensitiveSessionToken: () => Promise<string | null>;
  clearSensitiveSessionToken: () => Promise<void>;
  /** Check if the current biometric session is still valid */
  isSessionValid: () => Promise<boolean>;
  /** Get a user-facing explanation of session state */
  getSessionExplanation: () => Promise<string>;
  /** Update session timeout duration (in minutes) */
  setSessionTimeoutMinutes: (minutes: number) => Promise<void>;
  /** Clear the biometric session, forcing re-auth */
  resetSession: () => Promise<void>;
}

const SecurityContext = createContext<SecurityContextValue | null>(null);

const DEFAULT_SETTINGS: SecuritySettings = {
  biometricLockEnabled: false,
  sessionTimeoutMinutes: 5,
};

const PIN_DESCRIPTION_BY_REASON: Record<SecurityAuthReason, string> = {
  app_unlock: "Enter your fallback PIN to unlock QuickEx.",
  payment_authorization: "Enter your fallback PIN to authorize this payment.",
  sensitive_data_access: "Enter your fallback PIN to reveal sensitive data.",
  session_expired: "Your session has expired. Enter your fallback PIN to continue.",
};

function isValidPin(pin: string) {
  return /^\d{4,6}$/.test(pin);
}

type BiometricStatus = "available" | "no_hardware" | "not_enrolled" | "unsupported";

async function checkBiometricAvailability(): Promise<BiometricStatus> {
  if (Platform.OS === "web") return "unsupported";

  try {
    const hasHardware = await LocalAuthentication.hasHardwareAsync();
    if (!hasHardware) return "no_hardware";

    const enrolled = await LocalAuthentication.isEnrolledAsync();
    if (!enrolled) return "not_enrolled";

    return "available";
  } catch {
    return "unsupported";
  }
}

export function SecurityProvider({ children }: { children: React.ReactNode }) {
  const [settings, setSettings] = useState<SecuritySettings>(DEFAULT_SETTINGS);
  const [isReady, setIsReady] = useState(false);
  const [biometricStatus, setBiometricStatus] = useState<BiometricStatus>("unsupported");
  const isBiometricAvailable = biometricStatus === "available";
  const [hasPinConfigured, setHasPinConfigured] = useState(false);
  const [isAppLocked, setIsAppLocked] = useState(false);

  const [pinPromptVisible, setPinPromptVisible] = useState(false);
  const [pinPromptDescription, setPinPromptDescription] = useState(
    PIN_DESCRIPTION_BY_REASON.app_unlock,
  );
  const [pinInput, setPinInput] = useState("");
  const [pinError, setPinError] = useState<string | null>(null);
  const [verifyingPin, setVerifyingPin] = useState(false);

  const pinResolverRef = useRef<((result: boolean) => void) | null>(null);
  const shouldLockOnNextActiveRef = useRef(false);

  const initialize = useCallback(async () => {
    const [storedSettings, biometricAvailable, pinConfigured] =
      await Promise.all([
        getSecuritySettings(),
        checkBiometricAvailability(),
        hasFallbackPin(),
      ]);

    setSettings(storedSettings);
    setBiometricStatus(biometricAvailable);
    setHasPinConfigured(pinConfigured);
    setIsAppLocked(storedSettings.biometricLockEnabled);
    setIsReady(true);
  }, []);

  useEffect(() => {
    initialize();
  }, [initialize]);

  useEffect(() => {
    const subscription = AppState.addEventListener("change", (nextState) => {
      if (nextState !== "active") {
        shouldLockOnNextActiveRef.current = true;
        return;
      }

      if (
        nextState === "active" &&
        shouldLockOnNextActiveRef.current &&
        settings.biometricLockEnabled
      ) {
        setIsAppLocked(true);
      }
      shouldLockOnNextActiveRef.current = false;
    });

    return () => subscription.remove();
  }, [settings.biometricLockEnabled]);

  const openPinPrompt = useCallback((reason: SecurityAuthReason, fallbackReason?: string) => {
    return new Promise<boolean>((resolve) => {
      pinResolverRef.current = resolve;
      const defaultDesc = PIN_DESCRIPTION_BY_REASON[reason];
      setPinPromptDescription(
        fallbackReason ? `${fallbackReason}\n\n${defaultDesc}` : defaultDesc,
      );
      setPinInput("");
      setPinError(null);
      setPinPromptVisible(true);
    });
  }, []);

  const resolvePinPrompt = useCallback((result: boolean) => {
    if (pinResolverRef.current) {
      pinResolverRef.current(result);
      pinResolverRef.current = null;
    }
    setPinPromptVisible(false);
    setPinInput("");
    setPinError(null);
  }, []);

  const tryBiometricAuth = useCallback(
    async (
      reason: SecurityAuthReason,
    ): Promise<{ success: boolean; fallbackReason?: string }> => {
      if (!settings.biometricLockEnabled) {
        return { success: false, fallbackReason: "Biometric lock is disabled." };
      }

      if (biometricStatus === "no_hardware") {
        return {
          success: false,
          fallbackReason: "Biometric hardware is not available on this device.",
        };
      }

      if (biometricStatus === "not_enrolled") {
        return {
          success: false,
          fallbackReason: "No biometrics are enrolled on this device.",
        };
      }

      if (biometricStatus === "unsupported") {
        return { success: false };
      }

      const promptMessage =
        reason === "payment_authorization"
          ? "Authenticate to approve payment"
          : reason === "sensitive_data_access"
            ? "Authenticate to access sensitive data"
            : reason === "session_expired"
              ? "Authenticate to resume your session"
              : "Authenticate to unlock QuickEx";

      try {
        const result = await LocalAuthentication.authenticateAsync({
          promptMessage,
          disableDeviceFallback: true,
          cancelLabel: "Use PIN",
        });

        if (result.success) {
          return { success: true };
        }

        if (result.error === "lockout") {
          return {
            success: false,
            fallbackReason: "Biometric authentication is locked out due to too many attempts.",
          };
        }

        if (result.error === "not_enrolled") {
          return {
            success: false,
            fallbackReason: "No biometrics are enrolled on this device.",
          };
        }

        return { success: false };
      } catch {
        return { success: false };
      }
    },
    [biometricStatus, settings.biometricLockEnabled],
  );

  const authenticateForSensitiveAction = useCallback(
    async (reason: SecurityAuthReason) => {
      if (!settings.biometricLockEnabled) return true;

      // For non-high-risk reasons, check if the session is still valid
      if (reason !== "session_expired") {
        const sessionValid = await isBiometricSessionValid(
          settings.sessionTimeoutMinutes,
        );
        if (sessionValid) {
          // Session is still valid - record this access to keep session alive
          await recordBiometricAuth(reason);
          return true;
        }
        // Session expired - force re-auth with session_expired context
      }

      const biometricResult = await tryBiometricAuth(reason);
      if (biometricResult.success) {
        // Record successful auth as new session
        await recordBiometricAuth(reason);
        return true;
      }

      if (!hasPinConfigured) {
        // Fallback for users permanently locked out without a PIN (e.g., legacy edge case).
        // Since they cannot provide a PIN, we clear biometric lock to give them a path forward.
        const nextSettings: SecuritySettings = {
          ...settings,
          biometricLockEnabled: false,
        };
        await saveSecuritySettings(nextSettings);
        setSettings(nextSettings);
        setIsAppLocked(false);
        await clearBiometricSession();
        return false; // Authentication failed, but app is now unlocked to prevent permanent lockout
      }

      return openPinPrompt(reason, biometricResult.fallbackReason);
    },
    [
      hasPinConfigured,
      openPinPrompt,
      settings.biometricLockEnabled,
      settings.sessionTimeoutMinutes,
      tryBiometricAuth,
    ],
  );

  const unlockApp = useCallback(async () => {
    const authenticated = await authenticateForSensitiveAction("app_unlock");
    if (authenticated) {
      setIsAppLocked(false);
    }

    return authenticated;
  }, [authenticateForSensitiveAction]);

  const setBiometricLockEnabled = useCallback(
    async (enabled: boolean) => {
      if (enabled && !hasPinConfigured) {
        return {
          ok: false,
          error: "Set a fallback PIN first before enabling biometric lock.",
        };
      }

      const nextSettings: SecuritySettings = {
        ...settings,
        biometricLockEnabled: enabled,
      };

      await saveSecuritySettings(nextSettings);
      setSettings(nextSettings);

      if (!enabled) {
        setIsAppLocked(false);
        // Clear the biometric session when disabling lock
        await clearBiometricSession();
      } else {
        setIsAppLocked(true);
      }

      return { ok: true };
    },
    [hasPinConfigured, settings],
  );

  const savePin = useCallback(async (pin: string) => {
    if (!isValidPin(pin)) {
      return {
        ok: false,
        error: "PIN must be 4 to 6 digits.",
      };
    }

    await setFallbackPin(pin);
    setHasPinConfigured(true);

    return { ok: true };
  }, []);

  const saveSensitiveSessionToken = useCallback(async (token: string) => {
    await saveSensitiveToken(token);
  }, []);

  const getSensitiveSessionToken = useCallback(async () => {
    return getSensitiveToken();
  }, []);

  const clearSensitiveSessionToken = useCallback(async () => {
    await clearSensitiveToken();
  }, []);

  // ── New session timeout methods ─────────────────────────────────────────────

  const isSessionValid = useCallback(async () => {
    return isBiometricSessionValid(settings.sessionTimeoutMinutes);
  }, [settings.sessionTimeoutMinutes]);

  const getSessionExplanation = useCallback(async () => {
    return getSessionExpiryExplanation();
  }, []);

  const setSessionTimeoutMinutes = useCallback(
    async (minutes: number) => {
      const clampedMinutes = Math.max(1, Math.min(60, minutes));
      const nextSettings: SecuritySettings = {
        ...settings,
        sessionTimeoutMinutes: clampedMinutes,
      };
      await saveSecuritySettings(nextSettings);
      setSettings(nextSettings);
    },
    [settings],
  );

  const resetSession = useCallback(async () => {
    await clearBiometricSession();
  }, []);

  const contextValue = useMemo<SecurityContextValue>(
    () => ({
      isReady,
      isAppLocked,
      isBiometricAvailable,
      hasPinConfigured,
      settings,
      setBiometricLockEnabled,
      savePin,
      unlockApp,
      authenticateForSensitiveAction,
      saveSensitiveSessionToken,
      getSensitiveSessionToken,
      clearSensitiveSessionToken,
      isSessionValid,
      getSessionExplanation,
      setSessionTimeoutMinutes,
      resetSession,
    }),
    [
      authenticateForSensitiveAction,
      clearSensitiveSessionToken,
      getSensitiveSessionToken,
      hasPinConfigured,
      isAppLocked,
      isBiometricAvailable,
      isReady,
      isSessionValid,
      getSessionExplanation,
      savePin,
      saveSensitiveSessionToken,
      setBiometricLockEnabled,
      resetSession,
      setSessionTimeoutMinutes,
      settings,
      unlockApp,
    ],
  );

  // Handle successful PIN auth - record session and resolve
  const onSubmitPin = useCallback(async () => {
    if (!isValidPin(pinInput)) {
      setPinError("PIN must contain 4 to 6 digits.");
      return;
    }

    setVerifyingPin(true);
    const valid = await verifyFallbackPin(pinInput);
    setVerifyingPin(false);

    if (!valid) {
      setPinError("Incorrect PIN. Please try again.");
      return;
    }

    // Record successful PIN auth as a biometric session
    await recordBiometricAuth(pinPromptDescription.includes("session_expired")
      ? "session_expired"
      : pinPromptDescription.includes("payment")
        ? "payment_authorization"
        : pinPromptDescription.includes("sensitive")
          ? "sensitive_data_access"
          : "app_unlock");

    resolvePinPrompt(true);
  }, [pinInput, pinPromptDescription, resolvePinPrompt]);

  const onCancelPin = useCallback(() => {
    resolvePinPrompt(false);
  }, [resolvePinPrompt]);

  return (
    <SecurityContext.Provider value={contextValue}>
      {children}
      <PinAuthModal
        visible={pinPromptVisible}
        title="PIN Required"
        description={pinPromptDescription}
        pin={pinInput}
        errorMessage={pinError}
        submitting={verifyingPin}
        onPinChange={(value) => {
          setPinInput(value.replace(/[^0-9]/g, ""));
          if (pinError) setPinError(null);
        }}
        onSubmit={onSubmitPin}
        onCancel={onCancelPin}
      />
    </SecurityContext.Provider>
  );
}

export function useSecurity() {
  const ctx = useContext(SecurityContext);
  if (!ctx) {
    throw new Error("useSecurity must be used within SecurityProvider");
  }

  return ctx;
}