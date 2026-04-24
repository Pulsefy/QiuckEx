import * as Joi from "joi";

/**
 * Environment variable validation schema.
 * Validates all required and optional environment variables at startup.
 * Provides clear error messages for missing or invalid values.
 */
export const envSchema = Joi.object({
  // Server configuration
  PORT: Joi.number()
    .port()
    .default(4000)
    .description("Port number for the server"),

  // Network configuration (required)
  NETWORK: Joi.string()
    .valid("testnet", "mainnet")
    .required()
    .description("Stellar network to connect to (testnet or mainnet)"),

  // Supabase configuration (required for database operations)
  SUPABASE_URL: Joi.string()
    .uri({ scheme: ["http", "https"] })
    .required()
    .description("Supabase project URL"),

  SUPABASE_ANON_KEY: Joi.string()
    .min(1)
    .required()
    .description("Supabase anonymous key"),

  // Node environment
  NODE_ENV: Joi.string()
    .valid("development", "production", "test")
    .default("development")
    .description("Node environment"),

  // Username reservation limit (optional). Max usernames per wallet; omit for no limit.
  MAX_USERNAMES_PER_WALLET: Joi.number()
    .integer()
    .min(0)
    .optional()
    .description("Max usernames per wallet (optional; omit for no limit)"),

  // Cache configuration for transactions
  CACHE_MAX_ITEMS: Joi.number()
    .integer()
    .min(1)
    .default(500)
    .description("Maximum number of items to cache for transactions"),

  CACHE_TTL_MS: Joi.number()
    .integer()
    .min(1000)
    .default(60000)
    .description("Cache TTL in milliseconds for transaction responses"),

  // Stellar ingestion (optional; omit to disable)
  QUICKEX_CONTRACT_ID: Joi.string()
    .optional()
    .description(
      "Soroban contract ID to stream events from (enables Stellar ingestion service)",
    ),

  // ---------------------------------------------------------------------------
  // Notification providers (all optional; omit to disable that channel)
  // ---------------------------------------------------------------------------

  // SendGrid email channel
  SENDGRID_API_KEY: Joi.string()
    .optional()
    .description("SendGrid API key — enables email notification channel"),

  SENDGRID_FROM_EMAIL: Joi.string()
    .optional()
    .description("From address for SendGrid emails (e.g. noreply@quickex.to)"),

  // Expo push channel
  EXPO_ACCESS_TOKEN: Joi.string()
    .optional()
    .description(
      "Expo server access token — enhances push notification delivery priority",
    ),

  // Reconciliation worker configuration
  RECONCILIATION_BATCH_SIZE: Joi.number()
    .integer()
    .min(1)
    .max(500)
    .default(50)
    .description(
      "Max records per entity type processed per reconciliation run",
    ),

  // Rate limiting — optional bcrypt-hashed API keys (comma-separated)
  // Generate a hash: node -e "require('bcrypt').hash('MY_KEY', 10).then(console.log)"
  API_KEYS: Joi.string()
    .optional()
    .description(
      "Comma-separated list of bcrypt-hashed API keys for trusted clients. " +
        "Valid keys receive higher rate limits (120 req/min vs 20 req/min).",
    ),

  // Global HTTP rate-limiting profiles (all optional; defaults applied)
  RATE_LIMIT_PUBLIC_BURST_LIMIT: Joi.number()
    .integer()
    .min(1)
    .default(10)
    .description("Public traffic burst request limit"),
  RATE_LIMIT_PUBLIC_BURST_TTL_MS: Joi.number()
    .integer()
    .min(1000)
    .default(10000)
    .description("Public traffic burst window in milliseconds"),
  RATE_LIMIT_PUBLIC_SUSTAINED_LIMIT: Joi.number()
    .integer()
    .min(1)
    .default(20)
    .description("Public traffic sustained request limit"),
  RATE_LIMIT_PUBLIC_SUSTAINED_TTL_MS: Joi.number()
    .integer()
    .min(1000)
    .default(60000)
    .description("Public traffic sustained window in milliseconds"),

  RATE_LIMIT_AUTHENTICATED_BURST_LIMIT: Joi.number()
    .integer()
    .min(1)
    .default(40)
    .description("Authenticated traffic burst request limit"),
  RATE_LIMIT_AUTHENTICATED_BURST_TTL_MS: Joi.number()
    .integer()
    .min(1000)
    .default(10000)
    .description("Authenticated traffic burst window in milliseconds"),
  RATE_LIMIT_AUTHENTICATED_SUSTAINED_LIMIT: Joi.number()
    .integer()
    .min(1)
    .default(120)
    .description("Authenticated traffic sustained request limit"),
  RATE_LIMIT_AUTHENTICATED_SUSTAINED_TTL_MS: Joi.number()
    .integer()
    .min(1000)
    .default(60000)
    .description("Authenticated traffic sustained window in milliseconds"),

  RATE_LIMIT_WEBHOOKS_BURST_LIMIT: Joi.number()
    .integer()
    .min(1)
    .default(20)
    .description("Webhook traffic burst request limit"),
  RATE_LIMIT_WEBHOOKS_BURST_TTL_MS: Joi.number()
    .integer()
    .min(1000)
    .default(10000)
    .description("Webhook traffic burst window in milliseconds"),
  RATE_LIMIT_WEBHOOKS_SUSTAINED_LIMIT: Joi.number()
    .integer()
    .min(1)
    .default(60)
    .description("Webhook traffic sustained request limit"),
  RATE_LIMIT_WEBHOOKS_SUSTAINED_TTL_MS: Joi.number()
    .integer()
    .min(1000)
    .default(60000)
    .description("Webhook traffic sustained window in milliseconds"),

  RATE_LIMIT_KEY_ORDER: Joi.string()
    .default("user_id,api_key,ip")
    .description(
      "Preferred key order for rate-limit identity. Allowed values: user_id,api_key,ip",
    ),

  // ---------------------------------------------------------------------------
  // Sentry Error Monitoring (optional; omit to disable)
  // ---------------------------------------------------------------------------

  SENTRY_DSN: Joi.string()
    .uri({ scheme: ["http", "https"] })
    .optional()
    .description("Sentry DSN for error reporting — omit to disable Sentry"),

  SENTRY_ENVIRONMENT: Joi.string()
    .optional()
    .description(
      "Sentry environment tag (e.g. production, staging). Falls back to NODE_ENV.",
    ),

  SENTRY_RELEASE: Joi.string()
    .optional()
    .description("Sentry release identifier (e.g. quickex-backend@1.2.3)"),

  SENTRY_TRACES_SAMPLE_RATE: Joi.number()
    .min(0)
    .max(1)
    .optional()
    .default(1.0)
    .description(
      "Sentry performance traces sample rate (0.0 to 1.0). Default: 1.0",
    ),

  SENTRY_PROFILES_SAMPLE_RATE: Joi.number()
    .min(0)
    .max(1)
    .optional()
    .default(1.0)
    .description("Sentry profiling sample rate (0.0 to 1.0). Default: 1.0"),
});

/**
 * Interface for typed environment variables
 */
export interface EnvConfig {
  PORT: number;
  NETWORK: "testnet" | "mainnet";
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  NODE_ENV: "development" | "production" | "test";
  MAX_USERNAMES_PER_WALLET?: number;
  CACHE_MAX_ITEMS: number;
  CACHE_TTL_MS: number;
  QUICKEX_CONTRACT_ID?: string;
  SENDGRID_API_KEY?: string;
  SENDGRID_FROM_EMAIL?: string;
  EXPO_ACCESS_TOKEN?: string;
  RECONCILIATION_BATCH_SIZE: number;
  API_KEYS?: string;
  RATE_LIMIT_PUBLIC_BURST_LIMIT: number;
  RATE_LIMIT_PUBLIC_BURST_TTL_MS: number;
  RATE_LIMIT_PUBLIC_SUSTAINED_LIMIT: number;
  RATE_LIMIT_PUBLIC_SUSTAINED_TTL_MS: number;
  RATE_LIMIT_AUTHENTICATED_BURST_LIMIT: number;
  RATE_LIMIT_AUTHENTICATED_BURST_TTL_MS: number;
  RATE_LIMIT_AUTHENTICATED_SUSTAINED_LIMIT: number;
  RATE_LIMIT_AUTHENTICATED_SUSTAINED_TTL_MS: number;
  RATE_LIMIT_WEBHOOKS_BURST_LIMIT: number;
  RATE_LIMIT_WEBHOOKS_BURST_TTL_MS: number;
  RATE_LIMIT_WEBHOOKS_SUSTAINED_LIMIT: number;
  RATE_LIMIT_WEBHOOKS_SUSTAINED_TTL_MS: number;
  RATE_LIMIT_KEY_ORDER: string;
  SENTRY_DSN?: string;
  SENTRY_ENVIRONMENT?: string;
  SENTRY_RELEASE?: string;
  SENTRY_TRACES_SAMPLE_RATE: number;
  SENTRY_PROFILES_SAMPLE_RATE: number;
}
