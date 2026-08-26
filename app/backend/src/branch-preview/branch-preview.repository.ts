import { Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { SupabaseService } from '../supabase/supabase.service';
import { BranchPreviewEnvironment, CreateBranchPreviewDto, UpdateBranchPreviewDto } from './branch-preview.model';

@Injectable()
export class BranchPreviewRepository {
  private readonly logger = new Logger(BranchPreviewRepository.name);
  private readonly TABLE_NAME = 'branch_preview_environments';

  constructor(private readonly supabaseService: SupabaseService) {}

  /**
   * Create a new branch preview environment in the database
   */
  async create(dto: CreateBranchPreviewDto, ownerId: string): Promise<BranchPreviewEnvironment> {
    const client = this.supabaseService.getClient();
    const id = randomUUID();
    const now = new Date();
    const expiresAt = dto.ttlMs ? new Date(now.getTime() + dto.ttlMs) : null;

    const preview: Omit<BranchPreviewEnvironment, 'id' | 'createdAt' | 'updatedAt'> = {
      branchName: dto.branchName,
      apiUrl: dto.apiUrl,
      frontendUrl: dto.frontendUrl,
      network: dto.network,
      contractRegistryVersion: dto.contractRegistryVersion,
      isActive: true,
      isShared: dto.isShared ?? false,
      expiryExempt: dto.expiryExempt ?? false,
      lastActivityAt: now,
      expiresAt: expiresAt || undefined,
    };

    const { data, error } = await client
      .from(this.TABLE_NAME)
      .insert({
        id,
        branch_name: preview.branchName,
      owner_id: ownerId,
        api_url: preview.apiUrl,
        frontend_url: preview.frontendUrl,
        network: preview.network,
        contract_registry_version: preview.contractRegistryVersion,
        is_active: preview.isActive,
        is_shared: preview.isShared,
        expiry_exempt: preview.expiryExempt,
        last_activity_at: now.toISOString(),
        created_at: now.toISOString(),
        updated_at: now.toISOString(),
        expires_at: expiresAt?.toISOString(),
      })
      .select()
      .single();

    if (error) {
      this.logger.error(`Failed to create branch preview: ${error.message}`, error);
      throw new Error(`Database error: ${error.message}`);
    }

    this.logger.log(`Created branch preview for ${dto.branchName} with ID ${id}`);
    return this.mapDbToModel(data);
  }

  /**
   * Find a branch preview by branch name
   */
  async findByBranchName(branchName: string): Promise<BranchPreviewEnvironment | null> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from(this.TABLE_NAME)
      .select('*')
      .eq('branch_name', branchName.toLowerCase().trim())
      .single();

    if (error) {
      if (error.code !== 'PGRST116') { // Record not found is expected
        this.logger.error(`Error finding branch preview: ${error.message}`, error);
      }
      return null;
    }

    return this.mapDbToModel(data);
  }

    /**
   * Find a preview by its ID.
   */
  async findById(id: string): Promise<BranchPreviewEnvironment | null> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from(this.TABLE_NAME)
      .select('*')
      .eq('id', id)
      .single();

    if (error) {
      if (error.code !== 'PGRST116') {
        this.logger.error(`Error finding branch preview by id: ${error.message}`, error);
      }
      return null;
    }
    return this.mapDbToModel(data);
  }

  /**
   * Find all active branch previews
   */
  async findAll(includeInactive = false): Promise<BranchPreviewEnvironment[]> {
    const client = this.supabaseService.getClient();
    let query = client.from(this.TABLE_NAME).select('*');
    
    if (!includeInactive) {
      query = query.eq('is_active', true);
    }

    const { data, error } = await query.order('created_at', { ascending: false });

    if (error) {
      this.logger.error(`Error fetching branch previews: ${error.message}`, error);
      throw new Error(`Database error: ${error.message}`);
    }

    return data.map(this.mapDbToModel);
  }

  /**
   * Update an existing branch preview
   */
  async update(id: string, dto: UpdateBranchPreviewDto): Promise<BranchPreviewEnvironment> {
    const client = this.supabaseService.getClient();
    const now = new Date();
    const updateData: Record<string, unknown> = {
      updated_at: now.toISOString(),
    };

    if (dto.apiUrl) updateData.api_url = dto.apiUrl;
    if (dto.frontendUrl) updateData.frontend_url = dto.frontendUrl;
    if (dto.network) updateData.network = dto.network;
    if (dto.contractRegistryVersion) updateData.contract_registry_version = dto.contractRegistryVersion;
    if (dto.isActive !== undefined) updateData.is_active = dto.isActive;
    if (dto.isShared !== undefined) updateData.is_shared = dto.isShared;
    if (dto.expiryExempt !== undefined) updateData.expiry_exempt = dto.expiryExempt;
    if (dto.ttlMs) {
      updateData.expires_at = new Date(now.getTime() + dto.ttlMs).toISOString();
    }

    const { data, error } = await client
      .from(this.TABLE_NAME)
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (error) {
      this.logger.error(`Failed to update branch preview ${id}: ${error.message}`, error);
      throw new Error(`Database error: ${error.message}`);
    }

    this.logger.log(`Updated branch preview ${id}`);
    return this.mapDbToModel(data);
  }

  /**
   * Delete a branch preview
   */
  async delete(id: string): Promise<void> {
    const client = this.supabaseService.getClient();
    const { error } = await client
      .from(this.TABLE_NAME)
      .delete()
      .eq('id', id);

    if (error) {
      this.logger.error(`Failed to delete branch preview ${id}: ${error.message}`, error);
      throw new Error(`Database error: ${error.message}`);
    }

    this.logger.log(`Deleted branch preview ${id}`);
  }

  /**
   * Active previews eligible for auto-expiry evaluation (exempt/shared skipped in worker policy).
   */
  async findActiveForAutoExpiryEvaluation(): Promise<BranchPreviewEnvironment[]> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from(this.TABLE_NAME)
      .select('*')
      .eq('is_active', true);

    if (error) {
      this.logger.error(`Error fetching previews for auto-expiry: ${error.message}`, error);
      return [];
    }

    return data.map(this.mapDbToModel);
  }

  /**
   * Deactivate a preview after the auto-expiry worker marks it stale.
   */
  async deactivateForAutoExpiry(
    id: string,
    reason: string,
    now: Date,
  ): Promise<BranchPreviewEnvironment | null> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from(this.TABLE_NAME)
      .update({
        is_active: false,
        auto_expired_at: now.toISOString(),
        auto_expiry_reason: reason,
        updated_at: now.toISOString(),
      })
      .eq('id', id)
      .eq('is_active', true)
      .select()
      .maybeSingle();

    if (error) {
      this.logger.error(`Failed to auto-expire preview ${id}: ${error.message}`, error);
      return null;
    }

    if (!data) {
      return null;
    }

    return this.mapDbToModel(data);
  }

  /**
   * Record resolver activity for inactivity-based expiry.
   */
  async touchLastActivity(branchName: string): Promise<void> {
    const client = this.supabaseService.getClient();
    const now = new Date().toISOString();
    const { error } = await client
      .from(this.TABLE_NAME)
      .update({
        last_activity_at: now,
        updated_at: now,
      })
      .eq('branch_name', branchName.toLowerCase().trim())
      .eq('is_active', true);

    if (error) {
      this.logger.debug(`Could not touch last activity for ${branchName}: ${error.message}`);
    }
  }

  /**
   * Find all expired branch previews (legacy TTL-only query).
   */
  async findExpired(): Promise<BranchPreviewEnvironment[]> {
    const client = this.supabaseService.getClient();
    const now = new Date().toISOString();

    const { data, error } = await client
      .from(this.TABLE_NAME)
      .select('*')
      .not('expires_at', 'is', null)
      .lt('expires_at', now)
      .eq('is_active', true);

    if (error) {
      this.logger.error(`Error finding expired previews: ${error.message}`, error);
      return [];
    }

    return data.map(this.mapDbToModel);
  }

  /**
   * Map database record to internal model
   */
  private mapDbToModel(dbRecord: Record<string, unknown>): BranchPreviewEnvironment {
    return {
      id: dbRecord.id as string,
      branchName: dbRecord.branch_name as string,
      apiUrl: dbRecord.api_url as string,
      frontendUrl: dbRecord.frontend_url as string,
      network: dbRecord.network as 'testnet' | 'mainnet',
      contractRegistryVersion: dbRecord.contract_registry_version as string,
      isActive: dbRecord.is_active as boolean,
      isShared: Boolean(dbRecord.is_shared),
      expiryExempt: Boolean(dbRecord.expiry_exempt),
      createdAt: new Date(dbRecord.created_at as string),
      updatedAt: new Date(dbRecord.updated_at as string),
      lastActivityAt: dbRecord.last_activity_at
        ? new Date(dbRecord.last_activity_at as string)
        : undefined,
      expiresAt: dbRecord.expires_at ? new Date(dbRecord.expires_at as string) : undefined,
      autoExpiredAt: dbRecord.auto_expired_at
        ? new Date(dbRecord.auto_expired_at as string)
        : undefined,
      autoExpiryReason: dbRecord.auto_expiry_reason as string | undefined,
    };
  }
}