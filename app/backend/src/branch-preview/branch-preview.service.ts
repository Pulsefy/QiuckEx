import { Injectable, Logger } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { BranchPreviewCache } from './branch-preview.cache';
import { BranchPreviewRepository } from './branch-preview.repository';
import { BranchPreviewAutoExpiryService } from './branch-preview-auto-expiry.service';
import { AuditService } from '../audit/audit.service';
import { EnvRole } from '../permissions/role';
import { canModifyEnv, canDeleteEnv } from '../permissions/policy';
import {
  BranchPreviewEnvironment,
  CreateBranchPreviewDto,
  UpdateBranchPreviewDto,
  BranchPreviewResponseDto,
} from './branch-preview.model';

@Injectable()
export class BranchPreviewService {
  private readonly logger = new Logger(BranchPreviewService.name);
  private readonly FALLBACK_API_URL = process.env.FALLBACK_API_URL || 'https://api.example.com';
  private readonly FALLBACK_FRONTEND_URL = process.env.FALLBACK_FRONTEND_URL || 'https://app.example.com';
  private readonly FALLBACK_NETWORK = (process.env.NETWORK as 'testnet' | 'mainnet') || 'testnet';
  private readonly FALLBACK_CONTRACT_VERSION = 'latest';

  constructor(
    private readonly cache: BranchPreviewCache,
    private readonly repository: BranchPreviewRepository,
    private readonly auditService: AuditService,
    private readonly autoExpiryService: BranchPreviewAutoExpiryService,
  ) {
    this.logger.log('Branch preview service initialized');
  }

  /**
   * Get preview environment configuration for a branch
   * Returns fallback for unknown/stale branches
   */
  async getPreviewForBranch(branchName: string): Promise<BranchPreviewResponseDto> {
    const normalizedBranch = branchName.toLowerCase().trim();
    
    // Check cache first
    const cached = this.cache.get(normalizedBranch);
    if (cached && cached.isActive && this.isPreviewValid(cached)) {
      this.logger.debug(`Returning cached preview for ${normalizedBranch}`);
      void this.repository.touchLastActivity(normalizedBranch);
      return this.mapToResponse(cached);
    }

    // Cache miss or stale, fetch from database
    const preview = await this.repository.findByBranchName(normalizedBranch);
    if (preview && preview.isActive && this.isPreviewValid(preview)) {
      // Update cache
      this.cache.set(normalizedBranch, preview);
      void this.repository.touchLastActivity(normalizedBranch);
      this.logger.debug(`Returning fresh preview for ${normalizedBranch}`);
      return this.mapToResponse(preview);
    }

    // Return fallback for unknown, inactive, or expired branches
    this.logger.warn(`Returning fallback environment for branch: ${normalizedBranch}`);
    return this.getFallbackResponse();
  }

  /**
   * Admin: Create a new branch preview mapping
   */
  async createPreview(
    dto: CreateBranchPreviewDto,
    actorId: string,
    requestId?: string,
  ): Promise<BranchPreviewEnvironment> {
    // Actor becomes the owner of the new preview
    const preview = await this.repository.create(dto, actorId);
    
    // Update cache
    this.cache.set(preview.branchName, preview, dto.ttlMs);
    
    // Audit log
    await this.auditService.log(
      actorId,
      'branch_preview.created',
      preview.id,
      {
        branchName: preview.branchName,
        apiUrl: preview.apiUrl,
      },
      requestId,
    );

    return preview;
  }

  /**
   * Admin: Update an existing branch preview mapping
   */
  async updatePreview(
    id: string,
    dto: UpdateBranchPreviewDto,
    actorId: string,
    requestId?: string,
  ): Promise<BranchPreviewEnvironment> {
    // Retrieve existing preview to enforce permission
    const existing = await this.repository.findById(id);
    if (!existing) {
      throw new Error(`Branch preview ${id} not found`);
    }

    // Determine user role (assumed to be attached to actorId context elsewhere)
    const roleHeader = (global as any).requestUserRoles?.[actorId] as any; // placeholder for role lookup
    const role = roleHeader as any; // fallback if not found

    // Import policy check
    if (!canModifyEnv(actorId, role, existing)) {
      throw new Error('Forbidden: insufficient permissions to modify this preview');
    }

    const updated = await this.repository.update(id, dto);
    
    // Invalidate cache to force refresh
    this.cache.delete(updated.branchName);
    
    // Audit log
    await this.auditService.log(
      actorId,
      'branch_preview.updated',
      id,
      {
        branchName: updated.branchName,
        changes: Object.keys(dto),
      },
      requestId,
    );

    return updated;
  }

  /**
   * Admin: Delete a branch preview mapping
   */
  async deletePreview(
    id: string,
    actorId: string,
    requestId?: string,
  ): Promise<void> {
    // Retrieve existing preview for permission check
    const existing = await this.repository.findById(id);
    if (!existing) {
      throw new Error(`Branch preview ${id} not found`);
    }
    const roleHeader = (global as any).requestUserRoles?.[actorId] as any; // placeholder
    const role = roleHeader as any;
    if (!canDeleteEnv(actorId, role, existing)) {
      throw new Error('Forbidden: insufficient permissions to delete this preview');
    }

    await this.repository.delete(id);
    this.cache.clear(); // Clear cache to ensure old entries are purged
    
    // Audit log
    await this.auditService.log(
      actorId,
      'branch_preview.deleted',
      id,
      {},
      requestId,
    );
  }

  /**
   * Admin: List all branch previews
   */
  async listPreviews(includeInactive = false): Promise<BranchPreviewEnvironment[]> {
    return this.repository.findAll(includeInactive);
  }

  /**
   * Admin: Manually invalidate cache for a specific branch
   */
  async invalidateCache(
    branchName: string,
    actorId: string,
    requestId?: string,
  ): Promise<boolean> {
    const deleted = this.cache.delete(branchName);
    
    await this.auditService.log(
      actorId,
      'branch_preview.cache_invalidated',
      branchName,
      { success: deleted },
      requestId,
    );

    return deleted;
  }

  /**
   * Admin: Clear entire cache
   */
  async clearAllCache(
    actorId: string,
    requestId?: string,
  ): Promise<void> {
    this.cache.clear();
    
    await this.auditService.log(
      actorId,
      'branch_preview.cache_cleared',
      'all',
      {},
      requestId,
    );
  }

  /**
   * Cleanup stale previews (delegates to scheduled auto-expiry sweep).
   */
  async cleanupExpiredPreviews(): Promise<number> {
    return this.autoExpiryService.runAutoExpirySweep(uuidv4());
  }

  /**
   * Check if a preview environment is still valid (not expired)
   */
  private isPreviewValid(preview: BranchPreviewEnvironment): boolean {
    if (!preview.expiresAt) return true;
    return new Date() < preview.expiresAt;
  }

  /**
   * Map internal model to public response
   */
  private mapToResponse(preview: BranchPreviewEnvironment): BranchPreviewResponseDto {
    return {
      branchName: preview.branchName,
      apiUrl: preview.apiUrl,
      frontendUrl: preview.frontendUrl,
      network: preview.network,
      contractRegistryVersion: preview.contractRegistryVersion,
      isFallback: false,
    };
  }

  /**
   * Create fallback response for unknown branches
   */
  private getFallbackResponse(): BranchPreviewResponseDto {
    return {
      branchName: 'fallback',
      apiUrl: this.FALLBACK_API_URL,
      frontendUrl: this.FALLBACK_FRONTEND_URL,
      network: this.FALLBACK_NETWORK,
      contractRegistryVersion: this.FALLBACK_CONTRACT_VERSION,
      isFallback: true,
    };
  }
}