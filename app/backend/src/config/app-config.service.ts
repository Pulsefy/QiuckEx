import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { EnvConfig } from './env.schema';

/**
 * Typed configuration service with centralized accessors for environment variables.
 * All environment variables are validated at startup via Joi schema.
 */
@Injectable()
export class AppConfigService {
  constructor(private readonly configService: ConfigService<EnvConfig, true>) {}

  /**
   * Get the server port
   */
  get port(): number {
    return this.configService.get('PORT', { infer: true });
  }

  /**
   * Get the Stellar network (testnet or mainnet)
   */
  get network(): 'testnet' | 'mainnet' {
    return this.configService.get('NETWORK', { infer: true });
  }

  /**
   * Get the Supabase URL
   */
  get supabaseUrl(): string {
    return this.configService.get('SUPABASE_URL', { infer: true });
  }

  /**
   * Get the Supabase anonymous key
   */
  get supabaseAnonKey(): string {
    return this.configService.get('SUPABASE_ANON_KEY', { infer: true });
  }

  /**
   * Get the Node environment
   */
  get nodeEnv(): 'development' | 'production' | 'test' {
    return this.configService.get('NODE_ENV', { infer: true });
  }

  /**
   * Check if running in development mode
   */
  get isDevelopment(): boolean {
    return this.nodeEnv === 'development';
  }

  /**
   * Check if running in production mode
   */
  get isProduction(): boolean {
    return this.nodeEnv === 'production';
  }

  /**
   * Check if running on testnet
   */
  get isTestnet(): boolean {
    return this.network === 'testnet';
  }

  /**
   * Check if running on mainnet
   */
  get isMainnet(): boolean {
    return this.network === 'mainnet';
  }

  /**
   * Max usernames per wallet (optional). When not set, returns undefined (no limit).
   */
  get maxUsernamesPerWallet(): number | undefined {
    return this.configService.get('MAX_USERNAMES_PER_WALLET', { infer: true });
  }

  /**
   * Maximum number of items to cache for transactions
   */
  get cacheMaxItems(): number {
    return this.configService.get('CACHE_MAX_ITEMS', { infer: true });
  }

  /**
   * Cache TTL in milliseconds for transaction responses
   */
  get cacheTtlMs(): number {
    return this.configService.get('CACHE_TTL_MS', { infer: true });
  }

  /**
   * Max records processed per entity type per reconciliation run
   */
  get reconciliationBatchSize(): number {
    return this.configService.get('RECONCILIATION_BATCH_SIZE', { infer: true });
  }

  /**
   * QuickEx Soroban contract id (optional). Used for ingestion and soroban preflight.
   */
  get quickexContractId(): string | undefined {
    return this.configService.get('QUICKEX_CONTRACT_ID', { infer: true });
  }

  /**
   * Sentry DSN for error reporting. Undefined means Sentry is disabled.
   */
  get sentryDsn(): string | undefined {
    return this.configService.get('SENTRY_DSN', { infer: true });
  }

  /**
   * Supabase service role key (optional). Used for admin database operations.
   */
  get supabaseServiceRoleKey(): string | undefined {
    return this.configService.get('SUPABASE_SERVICE_ROLE_KEY', { infer: true });
  }

  /**
   * Custom Horizon URL (optional). Overrides network default if provided.
   */
  get horizonUrl(): string | undefined {
    return this.configService.get('HORIZON_URL', { infer: true });
  }

  /**
   * Stellar secret key (optional). Required for signing transactions.
   */
  get stellarSecretKey(): string | undefined {
    return this.configService.get('STELLAR_SECRET_KEY', { infer: true });
  }

  /**
   * Stellar public key (optional). The public key corresponding to the secret key.
   */
  get stellarPublicKey(): string | undefined {
    return this.configService.get('STELLAR_PUBLIC_KEY', { infer: true });
  }

  /**
   * Check if payment signing is configured (has secret key)
   */
  get isPaymentSigningConfigured(): boolean {
    return !!this.stellarSecretKey;
  }
}
