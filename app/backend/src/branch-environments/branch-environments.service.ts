import { Injectable, ForbiddenException, NotFoundException, BadRequestException } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { AuditService } from '../audit/audit.service';
import { BranchEnvironment, CreateEnvironmentDto, UpdateEnvironmentDto, GrantPermissionDto } from './dto/branch-environment.dto';

@Injectable()
export class BranchEnvironmentsService {
  private environments: BranchEnvironment[] = [];

  constructor(private readonly auditService: AuditService) {}

  async create(userId: string, dto: CreateEnvironmentDto): Promise<BranchEnvironment> {
    const env: BranchEnvironment = {
      id: randomUUID(),
      branchName: dto.branchName,
      ownerId: userId,
      status: 'provisioning',
      permissions: [],
    };
    this.environments.push(env);

    await this.auditService.log(
      userId,
      'environment.create',
      env.id,
      { branchName: env.branchName }
    );

    return env;
  }

  async modify(userId: string, userRole: string, id: string, dto: UpdateEnvironmentDto): Promise<BranchEnvironment> {
    const env = this.getEnvironment(id);
    this.assertCanModify(env, userId, userRole);

    Object.assign(env, dto);

    await this.auditService.log(
      userId,
      'environment.modify',
      env.id,
      { changes: dto }
    );

    return env;
  }

  async teardown(userId: string, userRole: string, id: string): Promise<void> {
    const env = this.getEnvironment(id);
    this.assertCanTeardown(env, userId, userRole);

    this.environments = this.environments.filter((e) => e.id !== id);

    await this.auditService.log(
      userId,
      'environment.teardown',
      id,
      { branchName: env.branchName }
    );
  }

  async grantPermission(
    actorId: string,
    actorRole: string,
    id: string,
    dto: GrantPermissionDto
  ): Promise<void> {
    const env = this.getEnvironment(id);
    
    // Only owner or admin can grant permissions
    if (env.ownerId !== actorId && actorRole !== 'admin') {
      throw new ForbiddenException('Only the environment owner or an admin can grant permissions');
    }

    if (env.ownerId === dto.userId) {
      throw new BadRequestException('Cannot grant permissions to the owner');
    }

    const existing = env.permissions.find(p => p.userId === dto.userId);
    if (existing) {
      existing.role = dto.role;
    } else {
      env.permissions.push({ userId: dto.userId, role: dto.role });
    }

    await this.auditService.log(
      actorId,
      'environment.grant_permission',
      env.id,
      { targetUserId: dto.userId, role: dto.role }
    );
  }

  private getEnvironment(id: string): BranchEnvironment {
    const env = this.environments.find((e) => e.id === id);
    if (!env) {
      throw new NotFoundException(`Environment ${id} not found`);
    }
    return env;
  }

  private assertCanModify(env: BranchEnvironment, userId: string, userRole: string) {
    if (userRole === 'admin') return;
    if (env.ownerId === userId) return;
    
    const permission = env.permissions.find(p => p.userId === userId);
    if (permission && permission.role === 'reviewer') return;
    
    throw new ForbiddenException('Insufficient permissions to modify this environment');
  }

  private assertCanTeardown(env: BranchEnvironment, userId: string, userRole: string) {
    if (userRole === 'admin') return;
    if (env.ownerId === userId) return;
    
    const permission = env.permissions.find(p => p.userId === userId);
    if (permission && permission.role === 'reviewer') return;
    
    throw new ForbiddenException('Insufficient permissions to teardown this environment');
  }
}
