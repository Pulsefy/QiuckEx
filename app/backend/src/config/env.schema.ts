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
}
