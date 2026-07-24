import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { SupabaseService } from '../supabase/supabase.service';
import {
  PreviewScope,
  CreatePreviewScopeDto,
} from './preview-scope.types';

@Injectable()
export class PreviewScopeService {
  private readonly logger = new Logger(PreviewScopeService.name);

  constructor(private readonly supabase: SupabaseService) {}

  async createScope(dto: CreatePreviewScopeDto): Promise<PreviewScope> {
    const { data, error } = await this.supabase
      .getClient()
      .from('preview_scopes')
      .insert({
        scope_id: dto.scopeId,
        branch_name: dto.branchName,
        github_pr_url: dto.githubPrUrl ?? null,
        owner_public_key: dto.ownerPublicKey ?? null,
        expires_at: dto.expiresAt.toISOString(),
      })
      .select()
      .single();

    if (error) {
      this.logger.error(`Failed to create preview scope: ${error.message}`);
      throw error;
    }

    return data as PreviewScope;
  }

  async getScope(scopeId: string): Promise<PreviewScope | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from('preview_scopes')
      .select('*')
      .eq('scope_id', scopeId)
      .maybeSingle();

    if (error) {
      this.logger.error(`Failed to fetch preview scope: ${error.message}`);
      throw error;
    }

    return data as PreviewScope | null;
  }

  async isValidScope(scopeId: string): Promise<boolean> {
    const scope = await this.getScope(scopeId);
    if (!scope) return false;

    const now = new Date();
    const expiresAt = new Date(scope.expires_at);
    return expiresAt > now;
  }

  async extendScope(scopeId: string, ttlMs: number): Promise<PreviewScope> {
    const scope = await this.getScope(scopeId);
    if (!scope) {
      throw new NotFoundException(`Preview scope not found: ${scopeId}`);
    }

    const newExpiresAt = new Date(Date.now() + ttlMs);

    const { data, error } = await this.supabase
      .getClient()
      .from('preview_scopes')
      .update({ expires_at: newExpiresAt.toISOString() })
      .eq('scope_id', scopeId)
      .select()
      .single();

    if (error) {
      this.logger.error(`Failed to extend preview scope: ${error.message}`);
      throw error;
    }

    return data as PreviewScope;
  }

  async deleteScope(scopeId: string): Promise<void> {
    await this.supabase
      .getClient()
      .from('preview_scopes')
      .delete()
      .eq('scope_id', scopeId);
  }

  async getExpiredScopes(): Promise<PreviewScope[]> {
    const now = new Date().toISOString();

    const { data, error } = await this.supabase
      .getClient()
      .from('preview_scopes')
      .select('*')
      .lt('expires_at', now);

    if (error) {
      this.logger.error(`Failed to fetch expired scopes: ${error.message}`);
      return [];
    }

    return (data ?? []) as PreviewScope[];
  }

  async cleanupExpiredScope(scopeId: string): Promise<{ deleted_from: string; row_count: number }[]> {
    const { data, error } = await this.supabase
      .getClient()
      .rpc('delete_expired_preview_scope_data', { p_scope_id: scopeId });

    if (error) {
      this.logger.error(`Failed to clean up scope ${scopeId}: ${error.message}`);
      return [];
    }

    await this.deleteScope(scopeId);

    this.logger.log(`Cleaned up preview scope ${scopeId}`);

    return (data ?? []) as { deleted_from: string; row_count: number }[];
  }

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async cleanupExpiredScopes(): Promise<void> {
    this.logger.log('Running expired preview scope cleanup...');
    const expired = await this.getExpiredScopes();
    let totalTables = 0;
    let totalRows = 0;

    for (const scope of expired) {
      const results = await this.cleanupExpiredScope(scope.scope_id);
      for (const r of results) {
        totalTables++;
        totalRows += r.row_count;
      }
    }

    if (expired.length > 0) {
      this.logger.log(
        `Cleanup complete: ${expired.length} scopes, ${totalTables} tables, ${totalRows} rows removed`,
      );
    }
  }
}
