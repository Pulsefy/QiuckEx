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
  async create(dto: CreateBranchPreviewDto): Promise<BranchPreviewEnvironment> {
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
      expiresAt: expiresAt || undefined,
    };

    const { data, error } = await client
      .from(this.TABLE_NAME)
      .insert({
        id,
        ...preview,
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
   * Find all expired branch previews
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
      createdAt: new Date(dbRecord.created_at as string),
      updatedAt: new Date(dbRecord.updated_at as string),
      expiresAt: dbRecord.expires_at ? new Date(dbRecord.expires_at as string) : undefined,
    };
  }
}