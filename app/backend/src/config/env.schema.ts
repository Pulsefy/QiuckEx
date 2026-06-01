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

  STELLAR_NETWORK: Joi.string()
    .valid("testnet", "mainnet")
    .optional()
    .description(
      "Optional alias for NETWORK; must match NETWORK when both are set",
    ),

  // Supabase configuration (required for database operations)
  SUPABASE_URL: Joi.string()
    .uri({ scheme: ["http", "https"] })
    .required()
    .description("Supabase project URL"),

  SUPABASE_ANON_KEY: Joi.string()
    .min(1)
    .required()
    .description("Supabase anonymous key"),

  SUPABASE_SERVICE_ROLE_KEY: Joi.string()
    .optional()
    .description("Supabase service role key for admin operations"),

  // Stellar Horizon configuration (required for blockchain operations)
  HORIZON_URL: Joi.string()
    .uri({ scheme: ["http", "https"] })
    .optional()
    .description("Custom Horizon URL (overrides network default)"),

  SOROBAN_RPC_URL: Joi.string()
    .uri({ scheme: ["http", "https"] })
    .optional()
    .description("Custom Soroban RPC URL (overrides network default)"),

  SOROBAN_RPC_URLS: Joi.string()
    .optional()
    .description("Comma-separated fallback Soroban RPC URLs for failover"),

  SOROBAN_RPC_TIMEOUT_MS: Joi.number()
    .integer()
    .min(1000)
    .default(10000)
    .description("Timeout in milliseconds for Soroban RPC requests"),

  SOROBAN_RPC_MAX_RETRIES: Joi.number()
    .integer()
    .min(1)
    .max(10)
    .default(3)
    .description("Max retry attempts for transient Soroban RPC failures"),

  STELLAR_EXPLORER_URL: Joi.string()
    .uri({ scheme: ["http", "https"] })
    .optional()
    .description("Custom Stellar explorer URL (overrides network default)"),

  // Stellar signing keys (required for payment operations)
  STELLAR_SECRET_KEY: Joi.string()
    .optional()
    .description(
      "Stellar account secret key for signing transactions (starts with S)",
    ),

  STELLAR_PUBLIC_KEY: Joi.string()
    .optional()
    .description("Stellar account public key (starts with G)"),

  // Node environment
  NODE_ENV: Joi.string()
    .valid("development", "production", "test")
    .default("development")
    .description("Node environment"),

  // CORS configuration
  CORS_ALLOWED_ORIGINS: Joi.string()
    .empty("")
    .optional()
    .description(
      "Comma-separated list of allowed CORS origins (e.g. https://quickex.to,https://app.quickex.to). " +
        "Required in production when no wildcard is desired.",
    ),

  CORS_VERCEL_PROJECT: Joi.string()
    .empty("")
    .optional()
    .description(
      "Vercel project slug (e.g. quickex-frontend). " +
        "When set, all preview URLs matching https://<slug>-*.vercel.app are allowed.",
    ),

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

  FEATURE_FLAGS_CACHE_TTL_MS: Joi.number()
    .integer()
    .min(1000)
    .default(15000)
    .description("Cache TTL in milliseconds for feature flag snapshots"),

  FEATURE_FLAGS_BOOTSTRAP_JSON: Joi.string()
    .empty("")
    .optional()
    .description(
      "Optional JSON array of bootstrap feature flags used when the store is unavailable",
    ),

  // Stellar ingestion (optional; omit to disable)
  QUICKEX_CONTRACT_ID: Joi.string()
    .empty("")
    .optional()
    .description(
      "Soroban contract ID to stream events from (enables Stellar ingestion service)",
    ),

  // ---------------------------------------------------------------------------
  // Notification providers (all optional; omit to disable that channel)
  // ---------------------------------------------------------------------------

  // SendGrid email channel
  SENDGRID_API_KEY: Joi.string()
    .empty("")
    .optional()
    .description("SendGrid API key — enables email notification channel"),

  SENDGRID_FROM_EMAIL: Joi.string()
    .empty("")
    .optional()
    .description("From address for SendGrid emails (e.g. noreply@quickex.to)"),

  // Expo push channel
  EXPO_ACCESS_TOKEN: Joi.string()
    .empty("")
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
    .empty("")
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
    .empty("")
    .optional()
    .description("Sentry DSN for error reporting — omit to disable Sentry"),

  SENTRY_ENVIRONMENT: Joi.string()
    .empty("")
    .optional()
    .description(
      "Sentry environment tag (e.g. production, staging). Falls back to NODE_ENV.",
    ),

  SENTRY_RELEASE: Joi.string()
    .empty("")
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

  // ---------------------------------------------------------------------------
  // Staging Environment Parity Configuration (optional)
  // ---------------------------------------------------------------------------

  // Enable environment parity checks at startup
  ENV_PARITY_CHECK_ENABLED: Joi.boolean()
    .default(false)
    .description("Enable environment parity validation checks at startup"),

  // Production base URL for parity comparison
  PRODUCTION_BASE_URL: Joi.string()
    .uri({ scheme: ["http", "https"] })
    .empty("")
    .optional()
    .description("Production API base URL for environment parity checks"),

  // Enable shadow traffic mode (read-only endpoint mirroring)
  SHADOW_TRAFFIC_ENABLED: Joi.boolean()
    .default(false)
    .description("Enable shadow traffic mode for selected read endpoints"),

  // Shadow traffic sample rate (0.0 to 1.0)
  SHADOW_TRAFFIC_SAMPLE_RATE: Joi.number()
    .min(0)
    .max(1)
    .default(0.1)
    .description("Sample rate for shadow traffic (0.0 to 1.0). Default: 0.1"),

  // Comma-separated list of endpoints to shadow (e.g., /api/links,/api/transactions)
  SHADOW_TRAFFIC_ENDPOINTS: Joi.string()
    .empty("")
    .default("/api/links,/api/transactions,/api/usernames")
    .description("Comma-separated list of read endpoints to shadow"),

  // Enable safe test data seeding for staging
  STAGING_SEED_DATA_ENABLED: Joi.boolean()
    .default(false)
    .description("Enable automatic test data seeding in staging environment"),

  // Staging environment identifier
  ENVIRONMENT_NAME: Joi.string()
    .valid("development", "staging", "production", "test")
    .optional()
    .description("Explicit environment name for parity tracking"),
});

/**
 * Interface for typed environment variables
 */
export interface EnvConfig {
  PORT: number;
  NETWORK: "testnet" | "mainnet";
  STELLAR_NETWORK?: "testnet" | "mainnet";
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  SUPABASE_SERVICE_ROLE_KEY?: string;
  HORIZON_URL?: string;
  SOROBAN_RPC_URL?: string;
  SOROBAN_RPC_URLS?: string;
  SOROBAN_RPC_TIMEOUT_MS: number;
  SOROBAN_RPC_MAX_RETRIES: number;
  STELLAR_EXPLORER_URL?: string;
  STELLAR_SECRET_KEY?: string;
  STELLAR_PUBLIC_KEY?: string;
  NODE_ENV: "development" | "production" | "test";
  CORS_ALLOWED_ORIGINS?: string;
  CORS_VERCEL_PROJECT?: string;
  MAX_USERNAMES_PER_WALLET?: number;
  CACHE_MAX_ITEMS: number;
  CACHE_TTL_MS: number;
  FEATURE_FLAGS_CACHE_TTL_MS: number;
  FEATURE_FLAGS_BOOTSTRAP_JSON?: string;
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
  ENV_PARITY_CHECK_ENABLED: boolean;
  PRODUCTION_BASE_URL?: string;
  SHADOW_TRAFFIC_ENABLED: boolean;
  SHADOW_TRAFFIC_SAMPLE_RATE: number;
  SHADOW_TRAFFIC_ENDPOINTS: string;
  STAGING_SEED_DATA_ENABLED: boolean;
  ENVIRONMENT_NAME?: "development" | "staging" | "production" | "test";
}
