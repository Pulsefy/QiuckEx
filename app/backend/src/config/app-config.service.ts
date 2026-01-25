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
}
