import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, SupabaseClient } from '@supabase/supabase-js';

@Injectable()
export class SupabaseService {
  private readonly logger = new Logger(SupabaseService.name);
  private readonly client: SupabaseClient | null;

  constructor(private readonly configService: ConfigService) {
    const url = this.configService.get<string>('SUPABASE_URL');
    const anonKey = this.configService.get<string>('SUPABASE_ANON_KEY');

    if (!url || !anonKey) {
      this.logger.warn(
        'Supabase env vars missing. Set SUPABASE_URL and SUPABASE_ANON_KEY to enable persistence.',
      );
      this.client = null;
      return;
    }

    this.client = createClient(url, anonKey, {
      auth: {
        persistSession: false,
      },
    });
  }

  getClient(): SupabaseClient | null {
    return this.client;
  }
}
