import { Injectable } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import { ApiKeyRecord, ApiKeyScope } from './api-keys.types';
import { CursorPayload, clampLimit, paginateResult } from '../common/pagination/cursor.util';

@Injectable()
export class ApiKeysRepository {
  constructor(private readonly supabase: SupabaseService) {}

  private get client() {
    return this.supabase.getClient();
  }

  async insert(data: {
    name: string;
    key_hash: string;
    key_prefix: string;
    scopes: ApiKeyScope[];
    owner_id: string | null;
    monthly_quota: number;
  }): Promise<ApiKeyRecord> {
    const { data: row, error } = await this.client
      .from('api_keys')
      .insert(data)
      .select()
      .single();

    if (error) throw error;
    return row as ApiKeyRecord;
  }

  async findAll(owner_id?: string): Promise<ApiKeyRecord[]> {
    let query = this.client
      .from('api_keys')
      .select('*')
      .eq('is_active', true)
      .order('created_at', { ascending: false });

    if (owner_id) {
      query = query.eq('owner_id', owner_id);
    }

    const { data, error } = await query;
    if (error) throw error;
    return (data as ApiKeyRecord[]) ?? [];
  }

  /**
   * Cursor-paginated variant of findAll.
   * Returns { data, next_cursor, has_more, limit }.
   */
  async findAllPaginated(
    owner_id: string | undefined,
    cursor: CursorPayload | null,
    limit?: number,
  ): Promise<{ data: ApiKeyRecord[]; next_cursor: string | null; has_more: boolean; limit: number }> {
    const effectiveLimit = clampLimit(limit);

    let query = this.client
      .from('api_keys')
      .select('*')
      .eq('is_active', true);

    if (owner_id) {
      query = query.eq('owner_id', owner_id);
    }

    // Apply cursor filter
    if (cursor) {
      query = query
        .lt('created_at', cursor.pk)
        .or(`created_at.eq.${cursor.pk},id.lt.${cursor.id}`);
    }

    query = query
      .order('created_at', { ascending: false })
      .order('id', { ascending: false })
      .limit(effectiveLimit + 1);

    const { data, error } = await query;
    if (error) throw error;

    const rows = (data as ApiKeyRecord[]) ?? [];
    const result = paginateResult(rows, effectiveLimit, 'created_at');

    return {
      data: result.data as ApiKeyRecord[],
      next_cursor: result.next_cursor,
      has_more: result.has_more,
      limit: effectiveLimit,
    };
  }

  async findById(id: string): Promise<ApiKeyRecord | null> {
    const { data, error } = await this.client
      .from('api_keys')
      .select('*')
      .eq('id', id)
      .eq('is_active', true)
      .single();

    // PGRST116 = "no rows returned" — treat as not found, not an error
    if (error?.code === 'PGRST116') return null;
    if (error) throw error;
    return data as ApiKeyRecord;
  }

  async findByPrefix(prefix: string): Promise<ApiKeyRecord[]> {
    const { data, error } = await this.client
      .from('api_keys')
      .select('*')
      .eq('key_prefix', prefix)
      .eq('is_active', true);

    if (error) throw error;
    return (data as ApiKeyRecord[]) ?? [];
  }

  async revoke(id: string): Promise<void> {
    const { error } = await this.client
      .from('api_keys')
      .update({ is_active: false, updated_at: new Date().toISOString() })
      .eq('id', id);

    if (error) throw error;
  }

  async updateKey(
    id: string,
    data: { key_hash: string; key_prefix: string },
  ): Promise<ApiKeyRecord> {
    // Fetch current to move hash to old_hash
    const current = await this.findById(id);
    if (!current) throw new Error('API key not found');

    const { data: row, error } = await this.client
      .from('api_keys')
      .update({
        key_hash: data.key_hash,
        key_prefix: data.key_prefix,
        key_hash_old: current.key_hash,
        rotated_at: new Date().toISOString(),
        request_count: 0,
        last_used_at: null,
        updated_at: new Date().toISOString(),
      })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    return row as ApiKeyRecord;
  }

  async incrementUsage(id: string): Promise<void> {
    const { error } = await this.client.rpc('increment_api_key_usage', {
      key_id: id,
    });
    if (error) throw error;
  }

  async getUsageSummary(owner_id?: string): Promise<{
    total_keys: number;
    total_requests: number;
    quota: number;
  }> {
    let query = this.client
      .from('api_keys')
      .select('request_count, monthly_quota')
      .eq('is_active', true);

    if (owner_id) {
      query = query.eq('owner_id', owner_id);
    }

    const { data, error } = await query;
    if (error) throw error;

    const rows = (data ?? []) as { request_count: number; monthly_quota: number }[];
    return {
      total_keys: rows.length,
      total_requests: rows.reduce((s, r) => s + r.request_count, 0),
      quota: rows.reduce((s, r) => s + r.monthly_quota, 0),
    };
  }
}
