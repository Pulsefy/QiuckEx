import React from "react";
import { act, fireEvent, render, waitFor } from "@testing-library/react-native";
import * as LocalAuthentication from "expo-local-authentication";

import { SecurityProvider, useSecurity } from "../hooks/use-security";
import * as SecurityService from "../services/security";
import type { SecurityAuthReason } from "../types/security";

jest.mock("expo-local-authentication", () => ({
  hasHardwareAsync: jest.fn(),
  isEnrolledAsync: jest.fn(),
  authenticateAsync: jest.fn(),
}));

jest.mock("../services/security", () => ({
  getSecuritySettings: jest.fn(),
  hasFallbackPin: jest.fn(),
  isBiometricSessionValid: jest.fn(),
  recordBiometricAuth: jest.fn(),
  verifyFallbackPin: jest.fn(),
}));

jest.mock("@/components/security/pin-auth-modal", () => {
  const React = require("react");
  const { Button, TextInput, View } = require("react-native");

  return {
    PinAuthModal: ({ visible, pin, onPinChange, onSubmit }: any) =>
      visible
        ? React.createElement(
            View,
            null,
            React.createElement(TextInput, {
              testID: "pin-input",
              value: pin,
              onChangeText: onPinChange,
            }),
            React.createElement(Button, {
              testID: "submit-pin",
              title: "Verify PIN",
              onPress: onSubmit,
            }),
          )
        : null,
  };
});

describe("PIN authentication reason tracking", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (SecurityService.getSecuritySettings as jest.Mock).mockResolvedValue({
      biometricLockEnabled: true,
      sessionTimeoutMinutes: 5,
    });
    (SecurityService.hasFallbackPin as jest.Mock).mockResolvedValue(true);
    (SecurityService.isBiometricSessionValid as jest.Mock).mockResolvedValue(
      false,
    );
    (SecurityService.verifyFallbackPin as jest.Mock).mockResolvedValue(true);
    (SecurityService.recordBiometricAuth as jest.Mock).mockResolvedValue(
      undefined,
    );
    (LocalAuthentication.hasHardwareAsync as jest.Mock).mockResolvedValue(true);
    (LocalAuthentication.isEnrolledAsync as jest.Mock).mockResolvedValue(true);
    (LocalAuthentication.authenticateAsync as jest.Mock).mockResolvedValue({
      success: false,
      error: "user_cancel",
    });
  });

  it.each<SecurityAuthReason>([
    "session_expired",
    "payment_authorization",
    "sensitive_data_access",
  ])("records %s after successful PIN re-authentication", async (reason) => {
    let authentication: Promise<boolean> | undefined;

    const TestConsumer = () => {
      const security = useSecurity();
      return (
        <Button
          testID="authenticate"
          title="Authenticate"
          disabled={!security.isReady}
          onPress={() => {
            authentication = security.authenticateForSensitiveAction(reason);
          }}
        />
      );
    };

    const { getByTestId } = render(
      <SecurityProvider>
        <TestConsumer />
      </SecurityProvider>,
    );

    await waitFor(() =>
      expect(getByTestId("authenticate").props.disabled).toBe(false),
    );

    fireEvent.press(getByTestId("authenticate"));
    await waitFor(() => expect(getByTestId("pin-input")).toBeTruthy());

    fireEvent.changeText(getByTestId("pin-input"), "1234");
    await act(async () => {
      fireEvent.press(getByTestId("submit-pin"));
      await authentication;
    });

    expect(SecurityService.recordBiometricAuth).toHaveBeenCalledWith(reason);
  });
});
