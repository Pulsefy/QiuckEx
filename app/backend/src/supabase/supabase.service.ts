import { Injectable, Logger } from '@nestjs/common';
import { createClient, SupabaseClient } from '@supabase/supabase-js';

import { AppConfigService } from '../config';
import {
  SupabaseError,
  SupabaseNetworkError,
  SupabaseUniqueConstraintError,
} from './supabase.errors';

@Injectable()
export class SupabaseService {
  private readonly logger = new Logger(SupabaseService.name);
  private readonly client: SupabaseClient;

  constructor(private readonly configService: AppConfigService) {
    // Environment variables are validated at startup via Joi schema,
    // so we can safely access them here without null checks
    const url = this.configService.supabaseUrl;
    const anonKey = this.configService.supabaseAnonKey;

    this.client = createClient(url, anonKey, {
      auth: {
        persistSession: false,
      },
    });

    this.logger.log('Supabase client initialized successfully');
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private handleError(error: any): never {
    if (error?.code === '23505') {
      throw new SupabaseUniqueConstraintError(error.message || 'Unique constraint violation', error);
    }
    // Match common network/timeout issues or PostgREST generic errors
    if (
      error?.message?.toLowerCase().includes('fetch') ||
      error?.message?.toLowerCase().includes('network') ||
      error?.code === 'PGRST301'
    ) {
      throw new SupabaseNetworkError(error.message || 'Network error connecting to Supabase', error);
    }
    throw new SupabaseError(error?.message || 'Unknown Supabase error', error?.code, error);
  }

  async insertUsername(username: string, publicKey: string): Promise<void> {
    const { error } = await this.client.from('usernames').insert({
      username,
      public_key: publicKey,
    });
    if (error) this.handleError(error);
  }

  async countUsernamesByPublicKey(publicKey: string): Promise<number> {
    const { count, error } = await this.client
      .from('usernames')
      .select('*', { count: 'exact', head: true })
      .eq('public_key', publicKey);
    if (error) this.handleError(error);
    return count ?? 0;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async listUsernamesByPublicKey(publicKey: string): Promise<any[]> {
    const { data, error } = await this.client
      .from('usernames')
      .select('id, username, public_key, created_at')
      .eq('public_key', publicKey)
      .order('created_at', { ascending: true });
    if (error) this.handleError(error);
    return data ?? [];
  }

  async checkHealth(): Promise<boolean> {
    try {
      const { error } = await this.client.from('usernames').select('id').limit(1);
      if (error) {
        this.logger.warn(`Supabase health check failed: ${error.message}`);
        return false;
      }
      return true;
    } catch (err) {
      this.logger.warn(`Supabase health check threw an error: ${(err as Error).message}`);
      return false;
    }
  }
}
