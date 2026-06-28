/**
 * Frontend environment variable validation.
 * Ensures all required variables are present at build/startup time.
 */

// Define required and optional environment variables
const requiredEnvVars = [
  "NEXT_PUBLIC_QUICKEX_API_URL",
  "NEXT_PUBLIC_STELLAR_NETWORK",
] as const;

const optionalEnvVars = [
  "NEXT_PUBLIC_SITE_URL",
  "NEXT_PUBLIC_ERROR_REPORTING_ENABLED",
  "NEXT_PUBLIC_APP_VERSION",
] as const;

type RequiredEnvVar = typeof requiredEnvVars[number];
type OptionalEnvVar = typeof optionalEnvVars[number];
type EnvVar = RequiredEnvVar | OptionalEnvVar;

// Validate environment variables
export function validateEnv() {
  const missing: RequiredEnvVar[] = [];
  const invalid: { key: EnvVar; reason: string }[] = [];

  // Check required variables
  for (const key of requiredEnvVars) {
    const value = process.env[key];
    if (!value || value.trim() === "") {
      missing.push(key);
    }
  }

  // Validate NEXT_PUBLIC_STELLAR_NETWORK
  const network = process.env.NEXT_PUBLIC_STELLAR_NETWORK;
  if (network && !["testnet", "mainnet"].includes(network.toLowerCase())) {
    invalid.push({
      key: "NEXT_PUBLIC_STELLAR_NETWORK",
      reason: `Must be either "testnet" or "mainnet", got "${network}"`,
    });
  }

  // Validate NEXT_PUBLIC_QUICKEX_API_URL is a valid URL
  const apiUrl = process.env.NEXT_PUBLIC_QUICKEX_API_URL;
  if (apiUrl) {
    try {
      new URL(apiUrl);
    } catch {
      invalid.push({
        key: "NEXT_PUBLIC_QUICKEX_API_URL",
        reason: `Must be a valid URL, got "${apiUrl}"`,
      });
    }
  }

  return { missing, invalid, isValid: missing.length === 0 && invalid.length === 0 };
}

// Get validated environment variables
export function getEnv() {
  const validation = validateEnv();
  if (!validation.isValid) {
    console.error("Environment validation failed:", {
      missing: validation.missing,
      invalid: validation.invalid,
    });
  }
  return {
    NEXT_PUBLIC_QUICKEX_API_URL: process.env.NEXT_PUBLIC_QUICKEX_API_URL!,
    NEXT_PUBLIC_STELLAR_NETWORK: process.env.NEXT_PUBLIC_STELLAR_NETWORK! as "testnet" | "mainnet",
    NEXT_PUBLIC_SITE_URL: process.env.NEXT_PUBLIC_SITE_URL,
    NEXT_PUBLIC_ERROR_REPORTING_ENABLED: process.env.NEXT_PUBLIC_ERROR_REPORTING_ENABLED,
    NEXT_PUBLIC_APP_VERSION: process.env.NEXT_PUBLIC_APP_VERSION,
  };
}
