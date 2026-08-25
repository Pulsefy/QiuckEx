import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';

import { AuditService } from '../audit/audit.service';
import { SyncBranchDeploymentDto } from './dto/sync-branch-deployment.dto';
import { BranchDeploymentRepository } from './deployment-sync.repository';
import {
  BranchDeployment,
  SyncBranchDeploymentInput,
} from './deployment-sync.model';

@Injectable()
export class BranchDeploymentService {
  private readonly logger = new Logger(BranchDeploymentService.name);

  constructor(
    private readonly repository: BranchDeploymentRepository,
    private readonly auditService: AuditService,
  ) {}

  /**
   * Ingest a branch/PR deployment event (BE-60).
   *
   * Duplicate deliveries of the same (branch, commit) at or before the stored
   * delivery time are idempotent — the existing record is returned unchanged.
   * Deliveries older than the newest already-recorded event for the branch are
   * rejected as stale, so out-of-order webhooks can never clobber newer state.
   */
  async syncDeployment(
    dto: SyncBranchDeploymentDto,
    actor: string,
  ): Promise<BranchDeployment> {
    const input = this.toInput(dto);

    const latest = await this.repository.findLatestForBranch(input.branchName);
    if (latest && latest.deliveredAt.getTime() > input.deliveredAt.getTime()) {
      this.logger.warn(
        `Rejected stale deployment delivery for ${input.branchName}@${input.commitSha.slice(0, 7)} ` +
          `(event ${input.deliveredAt.toISOString()} older than recorded ${latest.deliveredAt.toISOString()})`,
      );
      throw new ConflictException({
        error: 'STALE_DEPLOYMENT_EVENT',
        message: `A newer deployment (${latest.commitSha.slice(0, 7)}) is already recorded for branch "${input.branchName}"`,
        branchName: input.branchName,
        recordedCommitSha: latest.commitSha,
        recordedDeliveredAt: latest.deliveredAt.toISOString(),
      });
    }

    const existing = await this.repository.findByBranchAndCommit(
      input.branchName,
      input.commitSha,
    );
    if (existing && existing.deliveredAt.getTime() >= input.deliveredAt.getTime()) {
      this.logger.log(
        `Duplicate deployment delivery for ${input.branchName}@${input.commitSha.slice(0, 7)} — returning existing record`,
      );
      return existing;
    }

    const saved = await this.repository.upsert(input);

    await this.auditService.log(actor, 'branch_deployment.synced', saved.id, {
      branchName: saved.branchName,
      prNumber: saved.prNumber,
      commitSha: saved.commitSha,
      previewUrl: saved.previewUrl,
      status: saved.status,
      environment: saved.environment,
      deliveredAt: saved.deliveredAt.toISOString(),
    });

    return saved;
  }

  /**
   * Latest deployment metadata for a branch, optionally scoped to a PR.
   */
  async getDeploymentByBranch(
    branchName: string,
    prNumber?: number,
  ): Promise<BranchDeployment> {
    const found = await this.repository.findLatestForBranch(branchName, prNumber);
    if (!found) {
      throw new NotFoundException({
        error: 'DEPLOYMENT_NOT_FOUND',
        message: `No deployment metadata found for branch "${branchName}"${
          prNumber !== undefined ? ` and PR #${prNumber}` : ''
        }`,
      });
    }
    return found;
  }

  /**
   * Deployment history for a PR, newest first.
   */
  async getDeploymentsByPr(
    prNumber: number,
    limit = 20,
  ): Promise<BranchDeployment[]> {
    return this.repository.findByPrNumber(prNumber, limit);
  }

  private toInput(dto: SyncBranchDeploymentDto): SyncBranchDeploymentInput {
    return {
      branchName: dto.branchName.toLowerCase().trim(),
      prNumber: dto.prNumber,
      commitSha: dto.commitSha.toLowerCase(),
      previewUrl: dto.previewUrl,
      status: dto.status,
      environment: dto.environment ?? 'preview',
      deliveredAt: dto.deliveredAt ? new Date(dto.deliveredAt) : new Date(),
    };
  }
}
