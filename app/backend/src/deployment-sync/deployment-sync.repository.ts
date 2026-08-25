import { Injectable, Logger } from '@nestjs/common';

import { SupabaseService } from '../supabase/supabase.service';
import {
  BranchDeployment,
  SyncBranchDeploymentInput,
} from './deployment-sync.model';

@Injectable()
export class BranchDeploymentRepository {
  private readonly logger = new Logger(BranchDeploymentRepository.name);
  private readonly TABLE_NAME = 'branch_deployments';

  constructor(private readonly supabaseService: SupabaseService) {}

  /**
   * Insert or update the deployment for (branch, commit). The unique index
   * on (branch_name, commit_sha) makes re-deliveries of the same commit an
   * update rather than a duplicate row.
   */
  async upsert(input: SyncBranchDeploymentInput): Promise<BranchDeployment> {
    const client = this.supabaseService.getClient();
    const now = new Date().toISOString();

    const { data, error } = await client
      .from(this.TABLE_NAME)
      .upsert(
        {
          branch_name: this.normalizeBranch(input.branchName),
          pr_number: input.prNumber ?? null,
          commit_sha: input.commitSha,
          preview_url: input.previewUrl,
          status: input.status,
          environment: input.environment,
          delivered_at: input.deliveredAt.toISOString(),
          updated_at: now,
        },
        { onConflict: 'branch_name,commit_sha' },
      )
      .select()
      .single();

    if (error) {
      this.logger.error(
        `Failed to upsert branch deployment: ${error.message}`,
        error,
      );
      throw new Error(`Database error: ${error.message}`);
    }

    return this.mapDbToModel(data);
  }

  /**
   * Find the stored deployment for a specific (branch, commit) delivery.
   */
  async findByBranchAndCommit(
    branchName: string,
    commitSha: string,
  ): Promise<BranchDeployment | null> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from(this.TABLE_NAME)
      .select('*')
      .eq('branch_name', this.normalizeBranch(branchName))
      .eq('commit_sha', commitSha)
      .maybeSingle();

    if (error) {
      this.logger.error(
        `Error finding branch deployment: ${error.message}`,
        error,
      );
      return null;
    }

    return data ? this.mapDbToModel(data) : null;
  }

  /**
   * Find the most recent deployment for a branch, optionally scoped to a PR.
   */
  async findLatestForBranch(
    branchName: string,
    prNumber?: number,
  ): Promise<BranchDeployment | null> {
    const client = this.supabaseService.getClient();
    let query = client
      .from(this.TABLE_NAME)
      .select('*')
      .eq('branch_name', this.normalizeBranch(branchName));

    if (prNumber !== undefined) {
      query = query.eq('pr_number', prNumber);
    }

    const { data, error } = await query
      .order('delivered_at', { ascending: false })
      .limit(1);

    if (error) {
      this.logger.error(
        `Error fetching latest branch deployment: ${error.message}`,
        error,
      );
      return null;
    }

    return data && data.length > 0 ? this.mapDbToModel(data[0]) : null;
  }

  /**
   * List deployments for a PR, newest first.
   */
  async findByPrNumber(
    prNumber: number,
    limit = 20,
  ): Promise<BranchDeployment[]> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from(this.TABLE_NAME)
      .select('*')
      .eq('pr_number', prNumber)
      .order('delivered_at', { ascending: false })
      .limit(Math.min(limit, 100));

    if (error) {
      this.logger.error(
        `Error fetching PR deployments: ${error.message}`,
        error,
      );
      return [];
    }

    return (data ?? []).map((row) => this.mapDbToModel(row));
  }

  private normalizeBranch(branchName: string): string {
    return branchName.toLowerCase().trim();
  }

  private mapDbToModel(dbRecord: Record<string, unknown>): BranchDeployment {
    return {
      id: String(dbRecord.id),
      branchName: String(dbRecord.branch_name),
      prNumber: dbRecord.pr_number != null ? Number(dbRecord.pr_number) : undefined,
      commitSha: String(dbRecord.commit_sha),
      previewUrl: String(dbRecord.preview_url),
      status: dbRecord.status as BranchDeployment['status'],
      environment: String(dbRecord.environment),
      deliveredAt: new Date(String(dbRecord.delivered_at)),
      createdAt: new Date(String(dbRecord.created_at)),
      updatedAt: new Date(String(dbRecord.updated_at)),
    };
  }
}
