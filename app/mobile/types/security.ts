export interface SecuritySettings {
  biometricLockEnabled: boolean;
  /** Session timeout in minutes before biometric re-auth is required */
  sessionTimeoutMinutes: number;
}

export type SecurityAuthReason =
  | "app_unlock"
  | "payment_authorization"
  | "sensitive_data_access"
  | "session_expired";

/** High-risk actions that always require re-auth regardless of session state */
export type HighRiskAction = "send_payment" | "disconnect_wallet" | "clear_data";

export const HIGH_RISK_ACTIONS: readonly HighRiskAction[] = [
  "send_payment",
  "disconnect_wallet",
  "clear_data",
] as const;

export function isHighRiskAction(action: string): action is HighRiskAction {
  return HIGH_RISK_ACTIONS.includes(action as HighRiskAction);
}

export interface BiometricSessionInfo {
  /** ISO-8601 timestamp of the last successful biometric/PIN authentication */
  lastAuthenticatedAt: string;
  /** The auth reason that was last granted */
  lastAuthReason: SecurityAuthReason;
}

/** Default session timeout (in minutes) for low-risk activities */
export const DEFAULT_SESSION_TIMEOUT_MINUTES = 5;

/** Maximum allowed session timeout in minutes */
export const MAX_SESSION_TIMEOUT_MINUTES = 60;

/** Minimum allowed session timeout in minutes */
export const MIN_SESSION_TIMEOUT_MINUTES = 1;