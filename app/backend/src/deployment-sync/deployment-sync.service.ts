import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import { DeploymentWebhookPayloadDto } from './dto/webhook-payload.dto';
import { DeploymentResponseDto } from './dto/deployment-response.dto';

@Injectable()
export class DeploymentSyncService {
  private readonly logger = new Logger(DeploymentSyncService.name);

  constructor(private readonly supabaseService: SupabaseService) {}

  /**
   * Syncs deployment metadata.
   * Ensures idempotency and prevents stale updates by comparing event timestamps.
   */
  async syncDeployment(payload: DeploymentWebhookPayloadDto): Promise<DeploymentResponseDto> {
    const client = this.supabaseService.getClient();

    // 1. Check for existing deployment for this branch
    const { data: existing, error: fetchError } = await client
      .from('branch_deployments')
      .select('*')
      .eq('branch_name', payload.branchName)
      .maybeSingle();

    if (fetchError) {
      this.logger.error(`Failed to fetch deployment for branch ${payload.branchName}:`, fetchError.message);
      throw new Error(`Database error fetching deployment metadata: ${fetchError.message}`);
    }

    // 2. Prevent stale updates
    if (existing) {
      const existingTime = new Date(existing.event_timestamp).getTime();
      const incomingTime = new Date(payload.eventTimestamp).getTime();

      if (incomingTime < existingTime) {
        this.logger.warn(
          `Stale update received for branch ${payload.branchName}. ` +
          `Incoming event time (${payload.eventTimestamp}) is older than ` +
          `stored event time (${existing.event_timestamp}). Discarding update.`
        );
        return this.mapToResponseDto(existing);
      }
    }

    // 3. Upsert deployment metadata (idempotent / safe to replay)
    const { data: updated, error: upsertError } = await client
      .from('branch_deployments')
      .upsert(
        {
          branch_name: payload.branchName,
          pr_number: payload.prNumber ?? null,
          commit_sha: payload.commitSha,
          preview_url: payload.previewUrl ?? null,
          status: payload.status,
          event_timestamp: payload.eventTimestamp,
          updated_at: new Date().toISOString(),
        },
        {
          onConflict: 'branch_name',
        }
      )
      .select()
      .single();

    if (upsertError) {
      this.logger.error(`Failed to upsert deployment for branch ${payload.branchName}:`, upsertError.message);
      throw new Error(`Database error upserting deployment metadata: ${upsertError.message}`);
    }

    this.logger.log(`Successfully synced deployment for branch ${payload.branchName} (status: ${payload.status})`);
    return this.mapToResponseDto(updated);
  }

  /**
   * Retrieves deployment metadata by branch name.
   */
  async getDeploymentByBranch(branchName: string): Promise<DeploymentResponseDto> {
    const client = this.supabaseService.getClient();

    const { data, error } = await client
      .from('branch_deployments')
      .select('*')
      .eq('branch_name', branchName)
      .maybeSingle();

    if (error) {
      this.logger.error(`Failed to fetch deployment by branch name ${branchName}:`, error.message);
      throw new Error(`Database error: ${error.message}`);
    }

    if (!data) {
      throw new NotFoundException(`No deployment metadata found for branch: ${branchName}`);
    }

    return this.mapToResponseDto(data);
  }

  /**
   * Retrieves all deployment metadata entries associated with a PR number, sorted by event timestamp descending.
   */
  async getDeploymentsByPr(prNumber: number): Promise<DeploymentResponseDto[]> {
    const client = this.supabaseService.getClient();

    const { data, error } = await client
      .from('branch_deployments')
      .select('*')
      .eq('pr_number', prNumber)
      .order('event_timestamp', { ascending: false });

    if (error) {
      this.logger.error(`Failed to fetch deployments for PR ${prNumber}:`, error.message);
      throw new Error(`Database error: ${error.message}`);
    }

    if (!data || data.length === 0) {
      throw new NotFoundException(`No deployment metadata found for PR: ${prNumber}`);
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return data.map((row: any) => this.mapToResponseDto(row));
  }

  /**
   * Helper to map database rows (snake_case) to DTO objects (camelCase).
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private mapToResponseDto(row: any): DeploymentResponseDto {
    return {
      id: row.id,
      branchName: row.branch_name,
      prNumber: row.pr_number,
      commitSha: row.commit_sha,
      previewUrl: row.preview_url,
      status: row.status,
      eventTimestamp: row.event_timestamp,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
