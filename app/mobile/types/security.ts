export interface SecuritySettings {
  biometricLockEnabled: boolean;
}

export type SecurityAuthReason =
  | "app_unlock"
  | "payment_authorization"
  | "sensitive_data_access";
