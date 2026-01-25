import { Injectable, Logger } from '@nestjs/common';
import { createClient, SupabaseClient } from '@supabase/supabase-js';

import { AppConfigService } from '../config';

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

  getClient(): SupabaseClient {
    return this.client;
  }
}
