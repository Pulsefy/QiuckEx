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
    clearSensitiveToken,
    getSecuritySettings,
    getSensitiveToken,
    hasFallbackPin,
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
}

const SecurityContext = createContext<SecurityContextValue | null>(null);

const DEFAULT_SETTINGS: SecuritySettings = {
  biometricLockEnabled: false,
};

const PIN_DESCRIPTION_BY_REASON: Record<SecurityAuthReason, string> = {
  app_unlock: "Enter your fallback PIN to unlock QuickEx.",
  payment_authorization: "Enter your fallback PIN to authorize this payment.",
  sensitive_data_access: "Enter your fallback PIN to reveal sensitive data.",
};

function isValidPin(pin: string) {
  return /^\d{4,6}$/.test(pin);
}

async function checkBiometricAvailability() {
  if (Platform.OS === "web") return false;

  try {
    const hasHardware = await LocalAuthentication.hasHardwareAsync();
    const enrolled = await LocalAuthentication.isEnrolledAsync();
    return hasHardware && enrolled;
  } catch {
    return false;
  }
}

export function SecurityProvider({ children }: { children: React.ReactNode }) {
  const [settings, setSettings] = useState<SecuritySettings>(DEFAULT_SETTINGS);
  const [isReady, setIsReady] = useState(false);
  const [isBiometricAvailable, setIsBiometricAvailable] = useState(false);
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
    setIsBiometricAvailable(biometricAvailable);
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

  const openPinPrompt = useCallback((reason: SecurityAuthReason) => {
    return new Promise<boolean>((resolve) => {
      pinResolverRef.current = resolve;
      setPinPromptDescription(PIN_DESCRIPTION_BY_REASON[reason]);
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
    async (reason: SecurityAuthReason) => {
      if (!settings.biometricLockEnabled || !isBiometricAvailable) {
        return false;
      }

      const promptMessage =
        reason === "payment_authorization"
          ? "Authenticate to approve payment"
          : reason === "sensitive_data_access"
            ? "Authenticate to access sensitive data"
            : "Authenticate to unlock QuickEx";

      try {
        const result = await LocalAuthentication.authenticateAsync({
          promptMessage,
          disableDeviceFallback: true,
          cancelLabel: "Use PIN",
        });

        return result.success;
      } catch {
        return false;
      }
    },
    [isBiometricAvailable, settings.biometricLockEnabled],
  );

  const authenticateForSensitiveAction = useCallback(
    async (reason: SecurityAuthReason) => {
      if (!settings.biometricLockEnabled) return true;

      const biometricOk = await tryBiometricAuth(reason);
      if (biometricOk) return true;

      if (!hasPinConfigured) return false;

      return openPinPrompt(reason);
    },
    [
      hasPinConfigured,
      openPinPrompt,
      settings.biometricLockEnabled,
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
    }),
    [
      authenticateForSensitiveAction,
      clearSensitiveSessionToken,
      getSensitiveSessionToken,
      hasPinConfigured,
      isAppLocked,
      isBiometricAvailable,
      isReady,
      savePin,
      saveSensitiveSessionToken,
      setBiometricLockEnabled,
      settings,
      unlockApp,
    ],
  );

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

    resolvePinPrompt(true);
  }, [pinInput, resolvePinPrompt]);

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
