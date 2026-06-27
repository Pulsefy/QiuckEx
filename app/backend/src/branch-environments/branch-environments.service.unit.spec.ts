import { Test, TestingModule } from '@nestjs/common';
import { BranchEnvironmentsService } from './branch-environments.service';
import { AuditService } from '../audit/audit.service';
import { ForbiddenException, NotFoundException } from '@nestjs/common';

describe('BranchEnvironmentsService', () => {
  let service: BranchEnvironmentsService;
  let auditService: jest.Mocked<AuditService>;

  beforeEach(async () => {
    const mockAuditService = {
      log: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BranchEnvironmentsService,
        { provide: AuditService, useValue: mockAuditService },
      ],
    }).compile();

    service = module.get<BranchEnvironmentsService>(BranchEnvironmentsService);
    auditService = module.get(AuditService);
  });

  it('should allow owner to create, modify, and teardown an environment', async () => {
    const ownerId = 'user-1';
    
    // Create
    const env = await service.create(ownerId, { branchName: 'feat/test' });
    expect(env.ownerId).toBe(ownerId);
    expect(auditService.log).toHaveBeenCalledWith(ownerId, 'environment.create', env.id, { branchName: 'feat/test' });

    // Modify
    await service.modify(ownerId, 'contributor', env.id, { status: 'ready' });
    expect(auditService.log).toHaveBeenCalledWith(ownerId, 'environment.modify', env.id, { changes: { status: 'ready' } });

    // Teardown
    await service.teardown(ownerId, 'contributor', env.id);
    expect(auditService.log).toHaveBeenCalledWith(ownerId, 'environment.teardown', env.id, { branchName: 'feat/test' });
    
    await expect(service.modify(ownerId, 'contributor', env.id, { status: 'ready' })).rejects.toThrow(NotFoundException);
  });

  it('should block unauthorized contributors from modifying or tearing down environments', async () => {
    const ownerId = 'user-1';
    const unauthorizedUserId = 'user-2';
    
    const env = await service.create(ownerId, { branchName: 'feat/test' });
    
    await expect(service.modify(unauthorizedUserId, 'contributor', env.id, { status: 'ready' }))
      .rejects.toThrow(ForbiddenException);

    await expect(service.teardown(unauthorizedUserId, 'contributor', env.id))
      .rejects.toThrow(ForbiddenException);
  });

  it('should allow admin to modify and teardown any environment safely', async () => {
    const ownerId = 'user-1';
    const adminId = 'admin-1';
    
    const env = await service.create(ownerId, { branchName: 'feat/test' });
    
    await service.modify(adminId, 'admin', env.id, { status: 'ready' });
    await service.teardown(adminId, 'admin', env.id);
    
    expect(auditService.log).toHaveBeenCalledWith(adminId, 'environment.modify', env.id, expect.any(Object));
    expect(auditService.log).toHaveBeenCalledWith(adminId, 'environment.teardown', env.id, expect.any(Object));
  });

  it('should allow reviewer to modify and teardown an environment they review', async () => {
    const ownerId = 'user-1';
    const reviewerId = 'user-2';
    
    const env = await service.create(ownerId, { branchName: 'feat/test' });
    
    await service.grantPermission(ownerId, 'contributor', env.id, { userId: reviewerId, role: 'reviewer' });
    expect(auditService.log).toHaveBeenCalledWith(ownerId, 'environment.grant_permission', env.id, { targetUserId: reviewerId, role: 'reviewer' });

    await service.modify(reviewerId, 'contributor', env.id, { status: 'ready' });
    await service.teardown(reviewerId, 'contributor', env.id);
    
    expect(auditService.log).toHaveBeenCalledWith(reviewerId, 'environment.modify', env.id, expect.any(Object));
    expect(auditService.log).toHaveBeenCalledWith(reviewerId, 'environment.teardown', env.id, expect.any(Object));
  });
  
  it('should ensure destructive actions are audited', async () => {
    const ownerId = 'user-1';
    const env = await service.create(ownerId, { branchName: 'feat/test' });
    
    jest.clearAllMocks();
    
    await service.teardown(ownerId, 'contributor', env.id);
    expect(auditService.log).toHaveBeenCalledTimes(1);
    expect(auditService.log).toHaveBeenCalledWith(ownerId, 'environment.teardown', env.id, { branchName: 'feat/test' });
  });
});
